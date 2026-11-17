//go:build linux

package agent

import (
	"github.com/FyberLabs/hypermesh-host/internal/hostcrash"
	"github.com/FyberLabs/hypermesh-host/internal/nativecrash"
	"github.com/FyberLabs/hypermesh-host/internal/runtime"
	"os"
	"path/filepath"
)

func nativeContainer(cfg Config) runtime.ContainerCapture {
	if os.Getenv("HYPERMESH_HOST_NATIVE_CRASH_ENABLED") != "1" {
		return nil
	}
	sender, err := crashSender(cfg)
	if err != nil || sender == nil {
		return nil
	}
	state, err := filepath.Abs(filepath.Join(cfg.StateDir, "device.json"))
	if err != nil {
		return nil
	}
	state, err = filepath.EvalSymlinks(state)
	if err != nil {
		return nil
	}
	return nativecrash.NewContainerManager(state, func(report nativecrash.Report) {
		event, err := hostcrash.NewNativeEvent(cfg.TenantID, report.Captured, report.Code)
		if err == nil {
			sender(event)
		}
	})
}
