package agent

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/hostcrash"
	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
	"github.com/FyberLabs/hypermesh-host/internal/visorbridge"
)

// CrashReporter is enabled only by provisioned configuration and an enrollment
// that records acceptance of the current Host terms. No extra consent UI applies
// to Host analytics. Visor's independent consent policy is unchanged.
func CrashReporter(cfg Config) (func(time.Time), error) {
	// Optional Go reporting must not send an unsupported platform into the
	// monitor startup failure path. Native senders have their own capabilities.
	if !hostcrash.MonitorSupported() {
		return nil, nil
	}
	send, err := crashSender(cfg)
	if err != nil || send == nil {
		return nil, err
	}
	return func(captured time.Time) {
		event, e := hostcrash.NewEvent(cfg.TenantID, captured)
		if e == nil {
			send(event)
		}
	}, nil
}
func crashSender(cfg Config) (func(hostcrash.Event), error) {
	if os.Getenv("HYPERMESH_HOST_CRASH_ENABLED") != "1" {
		return nil, nil
	}
	if !EnrollmentTermsCurrent(cfg.StateDir) {
		return nil, nil
	}
	destination, err := hostcrash.ParseDestination(os.Getenv("HYPERMESH_HOST_CRASH_DSN"), os.Getenv("HYPERMESH_HOST_CRASH_REGISTRATION_URL"))
	if err != nil {
		return nil, hostcrash.ErrUnavailable
	}
	a := &Agent{cfg: cfg}
	original, err := a.loadState()
	if err != nil {
		return nil, hostcrash.ErrUnavailable
	}
	broker := os.Getenv("HYPERMESH_HOST_CRASH_REGISTRATION_URL")
	provider := machineidentity.Provider{Path: machineIdentityPath(cfg)}
	return func(event hostcrash.Event) {
		// A changed or retired enrollment cannot send the old process's report.
		current, e := a.loadState()
		if e != nil || current.DeviceID != original.DeviceID || current.DeviceSecret != original.DeviceSecret || !EnrollmentTermsCurrent(cfg.StateDir) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		credential := func(ctx context.Context) (string, error) {
			token, e := provider.ExistingToken(ctx, cfg.ControlPlaneURL, cfg.TenantID, original.DeviceID, "")
			if e != nil || !strings.HasPrefix(token, "hm_msi_") {
				return "", hostcrash.ErrUnavailable
			}
			return token, nil
		}
		// One attempt only. Errors intentionally contain no report, DSN or credentials.
		_ = destination.Send(ctx, cfg.TenantID, original.DeviceID, event, func(ctx context.Context, event hostcrash.Event) ([]byte, error) {
			return visorbridge.RegisterCrash(ctx, cfg.ControlPlaneURL, cfg.TenantID, original.DeviceID, broker, event.ID, event.Captured, event.Hash, credential)
		})
	}, nil
}
