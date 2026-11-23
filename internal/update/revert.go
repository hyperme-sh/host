package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// FileSHA256 rejects non-regular and oversized files before hashing.
func FileSHA256(path string) (string, error) {
	raw, err := boundedFile(path, maxAsset)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, ErrRejected
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrRejected
	}
	return raw, nil
}

// Revert accepts only an explicitly selected, retained, signed binary from the
// configured channel. It never downloads an arbitrary URL or changes a lease.
func Revert(ctx context.Context, cfg Config, target string, h Hooks) (Plan, error) {
	if runtime.GOOS != "linux" || !sha256Hex(target) {
		return Plan{}, ErrRejected
	}
	channel, err := ParseChannel(cfg.Channel)
	if err != nil || channel == "" {
		return Plan{Action: ActionReject, Reason: "revert requires a configured channel"}, ErrRejected
	}
	cfg.Channel = channel
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if cfg.Busy || (h.StillBusy != nil && h.StillBusy()) {
		return Plan{Action: ActionDefer}, nil
	}
	pub, err := boundedFile(cfg.PubKeyPath, 128<<10)
	if err != nil {
		return Plan{}, err
	}
	raw, err := boundedFile(filepath.Join(filepath.Dir(cfg.MarkerPath), "update-history", target+".json"), 1<<20)
	if err != nil {
		return Plan{}, err
	}
	var proof Evidence
	if json.Unmarshal(raw, &proof) != nil || proof.SHA256 != target {
		return Plan{}, ErrRejected
	}
	verify := func(sums, sig, key []byte, fps []string) error { return GPGVerify(sums, sig, key, fps) }
	if h.Verify != nil {
		verify = func(sums, sig, key []byte, _ []string) error { return h.Verify(sums, sig, key) }
	}
	man, err := proof.Validate(pub, cfg.Fingerprints, cfg.Channel, cfg.Arch, 1, verify)
	if err != nil {
		return Plan{}, err
	}
	if man.SoftwareControlProtocol != 1 || man.Build == cfg.BadBuild || man.Build >= cfg.CurrentBuild {
		return Plan{}, ErrRejected
	}
	paths, err := filepath.Glob(cfg.BinaryPath + ".pre-*")
	if err != nil {
		return Plan{}, err
	}
	var payload []byte
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := boundedFile(path, maxAsset)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) == target {
			payload = data
			break
		}
	}
	if payload == nil {
		return Plan{}, fmt.Errorf("signed rollback target is not retained")
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if h.StillBusy != nil && h.StillBusy() {
		return Plan{Action: ActionDefer}, nil
	}
	// Keep the rejected forward build out of the automatic channel after restart.
	if err := WriteBadBuild(filepath.Join(filepath.Dir(cfg.MarkerPath), BadName), max(cfg.CurrentBuild, cfg.BadBuild), ""); err != nil {
		return Plan{}, err
	}
	install := h.Install
	if install == nil {
		install = installFileKeeping(cfg.MarkerPath, h.Log)
	}
	backup, err := install(cfg.BinaryPath, payload, cfg.CurrentVersion)
	rollback := h.Rollback
	if rollback == nil {
		rollback = RollbackFile
	}
	restore := func(cause error) error {
		if backup != "" {
			if e := rollback(cfg.BinaryPath, backup); e != nil {
				return errors.Join(cause, e)
			}
		}
		if e := os.Remove(cfg.MarkerPath); e != nil && !os.IsNotExist(e) {
			return errors.Join(cause, e)
		}
		return cause
	}
	if err != nil {
		return Plan{}, restore(err)
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, restore(err)
	}
	if h.StillBusy != nil && h.StillBusy() {
		return Plan{}, restore(ErrRejected)
	}
	window := cfg.RollbackWindow
	if window <= 0 {
		window = 2 * time.Minute
	}
	if err := WriteMarker(cfg.MarkerPath, Marker{Binary: cfg.BinaryPath, Backup: backup, Version: man.Version, Deadline: time.Now().Add(window), Build: man.Build, ReleaseID: man.ReleaseID}); err != nil {
		return Plan{}, restore(err)
	}
	restart := h.Restart
	if restart == nil {
		restart = RestartAgent
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, restore(err)
	}
	if err := restart(ctx); err != nil {
		// systemd may stop this cgroup before systemctl returns. Keep the
		// candidate and marker so the next process can confirm or roll back.
		if errors.Is(err, errRestartInterrupted) {
			return Plan{}, err
		}
		return Plan{}, restore(err)
	}
	return Plan{Action: ActionInstall, Version: man.Version, Commit: man.Commit}, nil
}
