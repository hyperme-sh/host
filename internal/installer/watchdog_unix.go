//go:build linux || darwin

package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/update"
	"github.com/FyberLabs/hypermesh-host/internal/watchdog"
)

const (
	watchdogConfigPath = "/etc/hypermesh/recovery-watchdog.json"
	watchdogExecutable = "/usr/local/libexec/hypermesh-recovery"
	watchdogStateDir   = "/var/lib/hypermesh"
	watchdogAgent      = "/usr/local/bin/hypermesh-agent"
)

type watchdogConfig struct {
	Channel      string
	Build        int
	SHA256       string
	Fingerprints []string
	Key          []byte
}

type hostRecovery struct {
	config     watchdogConfig
	checkpoint watchdog.Checkpoint
	command    func(context.Context, string, ...string) ([]byte, error)
}

func rootWatchdogCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

func watchdogRead(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > limit {
		return nil, errors.New("unsafe recovery input")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("recovery input changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("recovery input unreadable")
	}
	return raw, nil
}

func (h hostRecovery) service(ctx context.Context) (running bool, down bool, err error) {
	if runtime.GOOS == "linux" {
		raw, err := h.command(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,MainPID,SubState", "--", "hypermesh-agent.service")
		if err != nil {
			return false, false, err
		}
		parts := strings.Fields(string(raw))
		sort.Strings(parts)
		return systemdRecoveryState(parts)
	}
	raw, err := h.command(ctx, "/bin/launchctl", "print", "system/com.fyberlabs.hypermesh-agent")
	if err != nil {
		// An unloaded daemon may be undergoing deliberate maintenance.
		return false, false, err
	}
	return launchdRecoveryState(string(raw))
}

func systemdRecoveryState(parts []string) (bool, bool, error) {
	if len(parts) != 4 || !strings.HasPrefix(parts[0], "ActiveState=") || parts[1] != "LoadState=loaded" {
		return false, false, errors.New("unable to identify the installed agent service")
	}
	rawPID, ok := strings.CutPrefix(parts[2], "MainPID=")
	pid, err := strconv.ParseUint(rawPID, 10, 32)
	if !ok || err != nil {
		return false, false, errors.New("unable to read the installed agent PID")
	}
	return parts[0] == "ActiveState=active" && pid > 0,
		pid == 0 && (parts[0] == "ActiveState=failed" ||
			(parts[0] == "ActiveState=activating" && parts[3] == "SubState=auto-restart")), nil
}

func launchdRecoveryState(raw string) (bool, bool, error) {
	text := "\n" + raw
	if !strings.Contains(text, "\n\tprogram = "+watchdogAgent+"\n") {
		return false, false, errors.New("unable to identify the installed agent LaunchDaemon")
	}
	return strings.Contains(text, "\n\tstate = running\n") && strings.Contains(text, "\n\tpid = "),
		strings.Contains(text, "\n\tstate = spawn scheduled\n") && !strings.Contains(text, "\n\tpid = "), nil
}

func (h hostRecovery) Inspect(ctx context.Context) (watchdog.Health, error) {
	var health watchdog.Health
	raw, err := watchdogRead(filepath.Join(watchdogStateDir, "device.json"), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return health, nil
	}
	if err != nil {
		return health, err
	}
	var device struct {
		ID     string `json:"device_id"`
		Secret string `json:"device_secret"`
	}
	if json.Unmarshal(raw, &device) != nil || device.ID == "" || device.Secret == "" {
		return health, nil
	}
	health.IdentityPresent = true
	running, down, err := h.service(ctx)
	if err != nil {
		return health, err
	}
	health.Running = running
	if installed, err := update.FileSHA256(watchdogAgent); err == nil {
		health.BinaryVerified = installed == h.config.SHA256
	}
	if !down {
		return health, nil
	}
	raw, err = watchdogRead(filepath.Join(watchdogStateDir, "sell.json"), 64<<10)
	if err == nil {
		var posture struct {
			SellState string `json:"sell_state"`
		}
		if json.Unmarshal(raw, &posture) != nil {
			return health, errors.New("selling posture unreadable")
		}
		health.OwnerPaused = posture.SellState == "paused"
	} else if !errors.Is(err, os.ErrNotExist) {
		return health, err
	}
	for _, name := range []string{"lease.json", "maintenance.json", update.MarkerName} {
		if _, err := os.Lstat(filepath.Join(watchdogStateDir, name)); !errors.Is(err, os.ErrNotExist) {
			return health, nil
		}
	}
	if runtime.GOOS == "linux" {
		_, err := os.Lstat("/run/reboot-required")
		health.RebootRequired = !errors.Is(err, os.ErrNotExist)
		raw, err = h.command(ctx, "/usr/bin/docker", "ps", "--filter", "name=^/hypermesh-", "--format", "{{.Names}}")
		health.OwnershipKnownIdle = err == nil && len(strings.TrimSpace(string(raw))) == 0
	} else {
		raw, err = h.command(ctx, "/bin/ps", "-axo", "comm=")
		health.OwnershipKnownIdle = err == nil && !strings.Contains(string(raw), "llama-server")
	}
	return health, nil
}

func (h hostRecovery) Save(state watchdog.State) error { return h.checkpoint.Save(state) }

func (h hostRecovery) idle(ctx context.Context) error {
	health, err := h.Inspect(ctx)
	if err != nil {
		return err
	}
	if health.Running || !health.IdentityPresent || !health.OwnershipKnownIdle || health.RebootRequired || health.OwnerPaused {
		return errors.New("agent profile is unavailable for local repair")
	}
	return nil
}

func (h hostRecovery) Restart(ctx context.Context) error {
	if err := h.idle(ctx); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		_, err := h.command(ctx, "/usr/bin/systemctl", "start", "--", "hypermesh-agent.service")
		return err
	}
	_, err := h.command(ctx, "/bin/launchctl", "kickstart", "system/com.fyberlabs.hypermesh-agent")
	return err
}

// Ordinary Linux updates retain signed release records. Include those records
// in the recovery floor so a stale public channel cannot undo an update.
func (h hostRecovery) signedFloor() (int, error) {
	floor := h.config.Build
	if runtime.GOOS != "linux" {
		return floor, nil
	}
	dir := filepath.Join(watchdogStateDir, "update-history")
	files, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return floor, nil
	}
	if err != nil {
		return 0, err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		raw, err := macRead(filepath.Join(dir, file.Name()), 0600, 1<<20)
		if err != nil {
			return 0, err
		}
		var proof update.Evidence
		var meta update.Manifest
		if json.Unmarshal(raw, &proof) != nil || json.Unmarshal(proof.Manifest, &meta) != nil {
			return 0, errors.New("unable to read signed update history")
		}
		if meta.Channel != h.config.Channel || meta.Build <= floor {
			continue
		}
		verified, err := proof.Validate(h.config.Key, h.config.Fingerprints, h.config.Channel,
			runtime.GOARCH, floor, update.GPGVerify)
		if err != nil {
			return 0, err
		}
		floor = verified.Build
	}
	return floor, nil
}

func (h hostRecovery) Repair(ctx context.Context) error {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return errors.New("recovery requires a system-managed GnuPG installation")
	}
	verifiedGPG, err := filepath.EvalSymlinks(gpg)
	if err != nil {
		return err
	}
	if err := macDirectory(filepath.Dir(verifiedGPG), false, false); err != nil {
		return errors.New("recovery GnuPG directory is not root managed")
	}
	info, err := os.Stat(verifiedGPG)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("recovery GnuPG executable is not protected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return errors.New("recovery GnuPG executable is not owned by root")
	}

	host := "https://api.hyperme.sh"
	if h.config.Channel == update.ChannelTest {
		host = "https://api.test.hyperme.sh"
	}
	channelURL := host + "/api/v1/hypermesh/public/host-releases/" + h.config.Channel
	pointer, err := fetchArtifact(ctx, channelURL, 64<<10)
	if err != nil {
		return err
	}
	var head releaseMetadata
	if json.Unmarshal(pointer, &head) != nil || head.Channel != h.config.Channel ||
		!releaseVersion.MatchString(head.Version) || !releaseCommit.MatchString(head.Commit) {
		return errors.New("invalid recovery channel head")
	}
	id := head.Version
	if head.Channel == update.ChannelTest {
		id = fmt.Sprintf("%d-%s", head.Build, head.Commit[:12])
	}
	if head.ReleaseID != id {
		return errors.New("invalid recovery release identity")
	}
	base := channelURL + "/" + id + "/"
	sums, err := fetchArtifact(ctx, base+"checksums.txt", 512<<10)
	if err != nil {
		return err
	}
	sig, err := fetchArtifact(ctx, base+"checksums.txt.sig", 128<<10)
	if err != nil {
		return err
	}
	manifest, err := fetchArtifact(ctx, base+"release.json", 64<<10)
	if err != nil {
		return err
	}
	floor, err := h.signedFloor()
	if err != nil {
		return err
	}
	release, err := watchdog.VerifyRelease(sums, sig, manifest, h.config.Key, h.config.Fingerprints,
		h.config.Channel, runtime.GOOS, runtime.GOARCH, floor)
	if err != nil {
		return err
	}
	if release.Manifest.ReleaseID != id || int64(release.Manifest.Build) != head.Build {
		return errors.New("signed recovery release differs from channel head")
	}
	payload, err := fetchArtifact(ctx, base+release.BinaryName(), update.MaxDownloadBytes)
	if err != nil {
		return err
	}
	if err := release.CheckPayload(payload); err != nil {
		return err
	}
	bad, err := update.ReadBadBuild(filepath.Join(watchdogStateDir, update.BadName))
	if err != nil {
		return err
	}
	if release.Manifest.Build == bad {
		return errors.New("recovery channel still points to a quarantined build")
	}
	// Advance the floor before replacing the executable. An interruption
	// after this write can retry the same authenticated release.
	next := h.config
	next.Build = release.Manifest.Build
	digest := sha256.Sum256(payload)
	next.SHA256 = hex.EncodeToString(digest[:])
	config, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := release.Replace(ctx, watchdogAgent, payload, func(ctx context.Context) error {
		if err := h.idle(ctx); err != nil {
			return err
		}
		return installWatchdogFile(watchdogConfigPath, config, 0600)
	}); err != nil {
		return err
	}
	return h.Restart(ctx)
}

func RunWatchdog(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	if len(args) == 1 && args[0] == "status" {
		if err := json.NewEncoder(out).Encode(watchdog.ReadNotice(watchdogStateDir)); err != nil {
			return 1
		}
		return 0
	}
	if len(args) != 0 || os.Geteuid() != 0 {
		fmt.Fprintln(diagnostic, "recovery-watchdog requires root; use the status argument to read a notice")
		return 2
	}
	raw, err := macRead(macPath("", watchdogConfigPath), 0600, 256<<10)
	var config watchdogConfig
	if err != nil || json.Unmarshal(raw, &config) != nil || config.Build <= 0 ||
		(config.Channel != update.ChannelTest && config.Channel != update.ChannelProd) ||
		len(config.Key) == 0 || len(config.Fingerprints) == 0 {
		fmt.Fprintln(diagnostic, "recovery watchdog configuration unavailable")
		return 1
	}
	unlock, err := update.LockProfile(filepath.Join(watchdogStateDir, update.ProfileLockName))
	if errors.Is(err, update.ErrProfileBusy) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	defer unlock()
	host := hostRecovery{config: config, checkpoint: watchdog.Checkpoint{Dir: watchdogStateDir}, command: rootWatchdogCommand}
	state, err := host.checkpoint.Load()
	if err != nil {
		_ = publishWatchdogNotice(watchdog.Notice{Reason: "state_unavailable", Message: "Host recovery cannot read its checkpoint. Check storage and file permissions."})
		fmt.Fprintln(diagnostic, "recovery watchdog state unreadable:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	result, err := watchdog.Check(ctx, host, state, time.Now())
	var notice watchdog.Notice
	switch result {
	case watchdog.IdentityMissing:
		notice = watchdog.Notice{Reason: "identity_missing", Message: "Host recovery could not read the original enrollment. Check the host and restore its original identity."}
	case watchdog.RetryExhausted:
		notice = watchdog.Notice{Reason: "retry_exhausted", Message: "Host recovery exhausted its automatic retries. Check the Host service logs and storage."}
	case watchdog.Healthy:
		_ = os.Remove(filepath.Join(watchdogStateDir, watchdog.NoticeFile))
	}
	if notice.Reason != "" {
		if err := publishWatchdogNotice(notice); err != nil {
			fmt.Fprintln(diagnostic, err)
			return 1
		}
		fmt.Fprintln(diagnostic, notice.Message)
	}
	fmt.Fprintln(out, result)
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	return 0
}

func publishWatchdogNotice(notice watchdog.Notice) error {
	raw, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	return installWatchdogFile(filepath.Join(watchdogStateDir, watchdog.NoticeFile), raw, 0600)
}
