package update

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxAsset = 64 << 20

// Config is one update check. There is no GitHub token on the host.
type Config struct {
	TargetSHA256   string // optional exact owner-requested target; never changes channel trust
	CurrentChannel string // immutable installed binary origin, not the selected channel
	Channel        string
	CurrentVersion string
	CurrentCommit  string
	CurrentBuild   int
	BadBuild       int
	Arch           string
	BinaryPath     string
	PubKeyPath     string
	Fingerprints   []string
	MarkerPath     string
	Busy           bool
	RollbackWindow time.Duration
	Now            time.Time
	Clock          func() time.Time // checked after download, immediately before restart
}

// Hooks replace the plane, gpg, install, and restart in tests.
// A nil Source is an error. Nil verify, install, and restart use the
// production implementations. StillBusy, when set, is called immediately
// before install and again after install, before restart. Rollback
// restores the previous binary when the second check is busy.
type Hooks struct {
	Source    UpdateSource
	Verify    func(checksums, sig, pubkey []byte) error
	Install   func(dest string, payload []byte, previous string) (string, error)
	Restart   func(ctx context.Context) error
	Rollback  func(dest, backup string) error
	ReadFile  func(path string) ([]byte, error)
	StillBusy func() bool
	// Log receives retention messages. Nil uses the default logger.
	Log *slog.Logger
}

// Tick checks the channel. A verification failure returns a reject
// plan and a nil error. Transport failures return an error so the
// agent keeps running and tries again later. Errors never carry a
// SAS query string.
func Tick(ctx context.Context, cfg Config, h Hooks) (Plan, error) {
	return tickForOS(runtime.GOOS, ctx, cfg, h)
}

func tickForOS(goos string, ctx context.Context, cfg Config, h Hooks) (Plan, error) {
	if goos != "linux" {
		return Plan{Action: ActionOff, Reason: "automatic updates require a qualified platform service lifecycle"}, nil
	}
	plan, err := tick(ctx, cfg, h)
	if err != nil {
		return Plan{}, scrub(err)
	}
	plan.Reason = RedactQuery(plan.Reason)
	return plan, nil
}

func tick(ctx context.Context, cfg Config, h Hooks) (Plan, error) {
	ch, err := ParseChannel(cfg.Channel)
	if err != nil {
		return Plan{Action: ActionReject, Reason: "bad channel"}, err
	}
	if ch == "" {
		return Plan{Action: ActionOff, Reason: "channel unset"}, nil
	}
	cfg.Channel = ch
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
		if !cfg.Now.IsZero() {
			clock = func() time.Time { return cfg.Now }
		}
	}
	window := cfg.RollbackWindow
	if window <= 0 {
		window = 2 * time.Minute
	}
	read := h.ReadFile
	if read == nil {
		read = osRead
	}
	pub, err := read(cfg.PubKeyPath)
	if err != nil || len(pub) == 0 {
		return Plan{Action: ActionReject, Reason: "update pubkey missing"}, nil
	}
	if h.Source == nil {
		return Plan{}, fmt.Errorf("hypermesh update: source is required")
	}
	cand, err := h.Source.Latest(ctx, cfg.Channel)
	if err != nil {
		return Plan{}, err
	}
	if cand == nil {
		return Plan{Action: ActionSkip, Reason: "nothing published"}, nil
	}
	if strings.TrimSpace(cand.Channel) != cfg.Channel {
		return Plan{Action: ActionReject, Reason: "plane channel does not match this box"}, nil
	}

	sumsArt, err := artifactByName(cand, ChecksumsName)
	if err != nil {
		return rejected(err)
	}
	sigArt, err := signatureArtifact(cand)
	if err != nil {
		return rejected(err)
	}
	manArt, err := artifactByName(cand, ManifestName)
	if err != nil {
		return rejected(err)
	}
	sums, err := fetchOne(ctx, h.Source, sumsArt)
	if err != nil {
		return rejected(err)
	}
	sig, err := fetchOne(ctx, h.Source, sigArt)
	if err != nil {
		return rejected(err)
	}
	verify := h.Verify
	if verify == nil {
		if len(cfg.Fingerprints) == 0 {
			return Plan{Action: ActionReject, Reason: "update fingerprints missing"}, nil
		}
		fps := append([]string(nil), cfg.Fingerprints...)
		verify = func(checksums, sig, pubkey []byte) error {
			return GPGVerify(checksums, sig, pubkey, fps)
		}
	}
	if err := verify(sums, sig, pub); err != nil {
		return Plan{Action: ActionReject, Reason: "checksum signature rejected"}, nil
	}
	if err := planeHashMatches(sums, ManifestName, manArt); err != nil {
		return rejected(err)
	}
	manRaw, err := fetchOne(ctx, h.Source, manArt)
	if err != nil {
		return rejected(err)
	}
	if err := CheckHash(sums, ManifestName, manRaw); err != nil {
		return Plan{Action: ActionReject, Reason: "release.json checksum rejected"}, nil
	}
	var man Manifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		return Plan{Action: ActionReject, Reason: "release.json rejected"}, nil
	}
	if man.Channel != cand.Channel || man.Version != cand.Version || !strings.EqualFold(strings.TrimSpace(man.Commit), strings.TrimSpace(cand.Commit)) || man.Build != cand.Build {
		return Plan{Action: ActionReject, Reason: "signed release.json does not match the plane"}, nil
	}
	if cfg.TargetSHA256 != "" && man.SoftwareControlProtocol != 1 {
		return Plan{Action: ActionReject, Reason: "requested target lacks remote software controls"}, nil
	}
	plan := DecideFromChannel(cfg.CurrentChannel, cfg.Channel, cfg.CurrentVersion, cfg.CurrentCommit, cfg.CurrentBuild, cfg.BadBuild, man, cfg.Busy)
	if plan.Action != ActionInstall {
		return plan, nil
	}
	binName, err := SelectBinary(string(sums), cfg.Arch)
	if err != nil {
		return Plan{Action: ActionReject, Reason: "no binary for this arch"}, nil
	}
	binArt, err := artifactByName(cand, binName)
	if err != nil {
		return rejected(err)
	}
	if cfg.TargetSHA256 != "" && cfg.TargetSHA256 != binArt.SHA256 {
		return Plan{Action: ActionReject, Reason: "requested target is not the channel candidate"}, nil
	}
	if err := planeHashMatches(sums, binName, binArt); err != nil {
		return rejected(err)
	}
	bin, err := fetchOne(ctx, h.Source, binArt)
	if err != nil {
		return rejected(err)
	}
	if err := CheckHash(sums, binName, bin); err != nil {
		return Plan{Action: ActionReject, Version: plan.Version, Commit: plan.Commit, Reason: "binary checksum rejected"}, nil
	}
	// Recheck immediately before install and restart. Decide already
	// saw Busy at the start of the check. A lease can arrive on the
	// owner socket while the artifacts download, and that must not
	// replace the binary or restart the agent.
	if h.StillBusy != nil && h.StillBusy() {
		return Plan{Action: ActionDefer, Version: plan.Version, Commit: plan.Commit, Reason: "busy"}, nil
	}
	install := h.Install
	if install == nil {
		install = installFileKeeping(cfg.MarkerPath, h.Log)
	}
	previous := cfg.CurrentVersion
	if strings.TrimSpace(previous) == "" {
		previous = cfg.CurrentCommit
	}
	// Keep independently verifiable evidence before exposing updated bytes.
	if h.Install == nil {
		if err := WriteEvidence(filepath.Dir(cfg.MarkerPath), Evidence{Schema: 1, Checksums: sums, Signature: sig, Manifest: manRaw, Binary: binName, SHA256: binArt.SHA256}); err != nil {
			return Plan{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	backup, err := install(cfg.BinaryPath, bin, previous)
	restore := func(cause error, removeMarker bool) error {
		rb := h.Rollback
		if rb == nil {
			rb = RollbackFile
		}
		if err := rb(cfg.BinaryPath, backup); err != nil {
			return errors.Join(cause, fmt.Errorf("restore previous agent: %w", err))
		}
		if removeMarker {
			if err := os.Remove(cfg.MarkerPath); err != nil && !os.IsNotExist(err) {
				return errors.Join(cause, fmt.Errorf("remove pending update: %w", err))
			}
		}
		return cause
	}
	if err != nil {
		if backup != "" {
			return Plan{}, restore(err, false)
		}
		return Plan{}, err
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, restore(err, false)
	}
	// A lease can arrive while the binary is replaced. Do not restart
	// over that job. Put the previous binary back and leave this
	// process running.
	if h.StillBusy != nil && h.StillBusy() {
		rb := h.Rollback
		if rb == nil {
			rb = RollbackFile
		}
		if err := rb(cfg.BinaryPath, backup); err != nil {
			return Plan{}, err
		}
		return Plan{Action: ActionDefer, Version: plan.Version, Commit: plan.Commit, Reason: "busy"}, nil
	}
	if err := WriteMarker(cfg.MarkerPath, Marker{
		Binary:    cfg.BinaryPath,
		Backup:    backup,
		Version:   plan.Version,
		Deadline:  clock().Add(window),
		Build:     man.Build,
		ReleaseID: man.ReleaseID,
	}); err != nil {
		return Plan{}, restore(err, true)
	}
	restart := h.Restart
	if restart == nil {
		restart = RestartAgent
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, restore(err, true)
	}
	if err := restart(ctx); err != nil {
		// systemd can stop the old agent and its systemctl child before
		// systemctl acknowledges the queued restart. On shutdown, keep the
		// candidate and marker so the next process can confirm or roll back.
		if errors.Is(ctx.Err(), context.Canceled) {
			return Plan{}, ctx.Err()
		}
		return Plan{}, restore(err, true)
	}
	return plan, nil
}

func rejected(err error) (Plan, error) {
	if err == nil {
		return Plan{}, nil
	}
	if errors.Is(err, ErrRejected) {
		return Plan{Action: ActionReject, Reason: RedactQuery(err.Error())}, nil
	}
	return Plan{}, err
}

func fetchOne(ctx context.Context, src UpdateSource, art Artifact) ([]byte, error) {
	if art.Size <= 0 || art.Size > maxAsset {
		return nil, fmt.Errorf("%w: size of %s", ErrRejected, art.Name)
	}
	if !sha256Hex(art.SHA256) {
		return nil, fmt.Errorf("%w: sha256 of %s", ErrRejected, art.Name)
	}
	body, err := src.Fetch(ctx, art.URL, art.Size)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != art.Size {
		return nil, fmt.Errorf("%w: size of %s", ErrRejected, art.Name)
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	want := strings.ToLower(strings.TrimSpace(art.SHA256))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return nil, fmt.Errorf("%w: sha256 of %s", ErrRejected, art.Name)
	}
	return body, nil
}

// planeHashMatches requires the plane's sha256 for name to be the
// digest in the signed checksum file. The plane does not choose the
// digest the agent installs.
func planeHashMatches(checksums []byte, name string, art Artifact) error {
	want, err := checksumFor(string(checksums), name)
	if err != nil {
		return err
	}
	got := strings.ToLower(strings.TrimSpace(art.SHA256))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("%w: plane sha256 does not match signed checksums for %s", ErrRejected, name)
	}
	return nil
}

func osRead(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// RestartAgent queues a restart for the standard agent service.
func RestartAgent(ctx context.Context) error {
	return restart(ctx, "systemctl", "--no-block", "restart", AgentUnit)
}

// RestartInstalledAgent maps only the installer-owned isolated paths to
// their units. A supplied unit name is never accepted from update metadata.
func RestartInstalledAgent(ctx context.Context, binaryPath, stateDir string) error {
	unit := AgentUnit
	switch {
	case binaryPath == "/etc/hypermesh-halo-test/hypermesh-agent" && stateDir == "/var/lib/hypermesh-halo-test":
		unit = "hypermesh-halo-test-agent.service"
	case binaryPath == "/etc/hypermesh-forum-test/hypermesh-agent" && stateDir == "/var/lib/hypermesh-forum-test":
		unit = "hypermesh-forum-test-agent.service"
	case strings.HasPrefix(binaryPath, "/etc/hypermesh-halo-test/"),
		strings.HasPrefix(binaryPath, "/etc/hypermesh-forum-test/"),
		stateDir == "/var/lib/hypermesh-halo-test", stateDir == "/var/lib/hypermesh-forum-test":
		return fmt.Errorf("hypermesh update: installed profile paths do not match")
	}
	return restart(ctx, "systemctl", "--no-block", "restart", unit)
}

func restart(ctx context.Context, name string, args ...string) error {
	if !restartAllowed(name, args) {
		return fmt.Errorf("hypermesh update: refusing to run %s", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hypermesh update: systemctl restart %s", args[2])
	}
	return nil
}

func restartAllowed(name string, args []string) bool {
	if name != "systemctl" || len(args) != 3 || args[0] != "--no-block" || args[1] != "restart" {
		return false
	}
	switch args[2] {
	case AgentUnit, "hypermesh-halo-test-agent.service", "hypermesh-forum-test-agent.service":
		return true
	default:
		return false
	}
}
