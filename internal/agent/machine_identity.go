package agent

import (
	"context"
	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
	"path/filepath"
)

// machineIdentityPath resolves the checkpoint path. The identity lock only
// accepts absolute paths, and HYPERMESH_STATE_DIR may be relative.
func machineIdentityPath(cfg Config) string {
	path := filepath.Join(cfg.StateDir, "machine-identity.json")
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func machineAPIClient(cfg Config) *api.Client {
	c := api.NewClient(cfg.ControlPlaneURL, cfg.TenantID)
	p := machineidentity.Provider{Path: machineIdentityPath(cfg)}
	c.Credential = func(ctx context.Context) (string, error) {
		token, err := p.ExistingToken(ctx, cfg.ControlPlaneURL, cfg.TenantID, c.DeviceID, c.DeviceSecret)
		if err != nil || cfg.ManagedDeviceID == "" || token != c.DeviceSecret {
			return token, err
		}
		// Managed token-enrolled hosts without a signing checkpoint use
		// the device ID as their legacy first-binding context. An existing
		// owner registration always retains the request in its checkpoint.
		return p.Token(ctx, cfg.ControlPlaneURL, cfg.TenantID, c.DeviceID, c.DeviceID, c.DeviceSecret)
	}
	c.InvalidateCredential = p.Invalidate
	return c
}

// Model hosts always bind a signing key after re-enrollment, including legacy
// hosts that never created a checkpoint. Supervisors keep enrollment secrets.
func retireMachineIdentity(ctx context.Context, cfg Config, device string) error {
	p := machineidentity.Provider{Path: machineIdentityPath(cfg)}
	return p.RetireEnrollment(ctx, device, !cfg.SupervisorHost())
}
