package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/hostcrash"
	"github.com/FyberLabs/hypermesh-host/internal/nativecrash"
	"github.com/FyberLabs/hypermesh-host/internal/runtime"
)

func nativeMetal(cfg Config) *runtime.Metal {
	metal := runtime.NewMetal()
	if os.Getenv("HYPERMESH_HOST_NATIVE_CRASH_ENABLED") != "1" || !nativecrash.Supported() {
		return metal
	}
	sender, err := crashSender(cfg)
	if err != nil || sender == nil {
		return metal
	}
	statePath, err := filepath.Abs(filepath.Join(cfg.StateDir, "device.json"))
	if err != nil {
		return metal
	}
	statePath, err = filepath.EvalSymlinks(statePath)
	if err != nil {
		return metal
	}
	metal.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if name == metal.Bin {
			output, err := nativecrash.Run(ctx, name, args, statePath, func(report nativecrash.Report) {
				event, e := hostcrash.NewNativeEvent(cfg.TenantID, report.Captured, report.Code)
				if e == nil {
					sender(event)
				}
			})
			// Refused preparation happened before execution; preserve normal worker
			// availability without capture. Never rerun a process that already started.
			if !errors.Is(err, nativecrash.ErrUnavailable) {
				return output, err
			}
		}
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	return metal
}
