//go:build !linux

package agent

import (
	"context"

	"github.com/FyberLabs/hypermesh-host/internal/api"
)

func (a *Agent) rebootHealth() api.HostHealth { return api.HostHealth{} }

func (a *Agent) verifyManagedReboot(context.Context, api.HostHealth, *api.HostHealth, string, string, api.HeartbeatResponse) {
}
