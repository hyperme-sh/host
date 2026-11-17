//go:build linux

package nativecrash

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func removeRun(run string) error {
	var raw, parent syscall.Stat_t
	if syscall.Stat(filepath.Join(run, "database"), &raw) == nil && syscall.Stat(run, &parent) == nil && raw.Dev != parent.Dev {
		if installedLibrary(containerHelper) != nil {
			return ErrUnavailable
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, containerHelper, "purge", filepath.Base(run)).Run() != nil {
			return ErrUnavailable
		}
		return nil
	}
	return os.RemoveAll(run)
}
