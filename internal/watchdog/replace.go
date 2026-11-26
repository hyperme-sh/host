package watchdog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FyberLabs/hypermesh-host/internal/update"
)

// Replace installs authenticated bytes over a missing or damaged executable.
// The caller supplies the fixed installer-owned target and keeps the shared
// profile lock held. Recheck must establish that the service is still down
// and that workload ownership is clear immediately before the rename.
func (r Release) Replace(ctx context.Context, target string, payload []byte, recheck func(context.Context) error) error {
	if len(payload) == 0 || len(payload) > update.MaxDownloadBytes ||
		!filepath.IsAbs(target) || recheck == nil {
		return errors.New("invalid watchdog replacement")
	}
	if err := update.CheckHash(r.checksums, r.BinaryName(), payload); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if info != nil && !info.Mode().IsRegular() {
		return errors.New("unsafe installed Host executable")
	}
	dir := filepath.Dir(target)
	staged, err := os.CreateTemp(dir, ".hypermesh-repair-")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if _, err := staged.Write(payload); err != nil {
		return err
	}
	if err := staged.Chmod(0755); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := recheck(ctx); err != nil {
		return fmt.Errorf("watchdog repair deferred: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := os.Lstat(target)
	if info == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("Host executable appeared during repair")
		}
	} else if err != nil || !os.SameFile(info, current) {
		return errors.New("Host executable changed during repair")
	}
	if err := os.Rename(staged.Name(), target); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
