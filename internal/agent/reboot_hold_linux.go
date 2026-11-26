package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/hardware"
)

const rebootHoldFile = "reboot-hold.json"

type rebootHold struct {
	PendingBoot  string `json:"pending_boot"`
	VerifiedBoot string `json:"verified_boot,omitempty"`
}

func readRebootHold(path string) (rebootHold, error) {
	var hold rebootHold
	data, err := os.ReadFile(path)
	if err != nil {
		return hold, err
	}
	if err := json.Unmarshal(data, &hold); err != nil {
		return hold, err
	}
	if hold.PendingBoot == "" || hold.PendingBoot == hold.VerifiedBoot {
		return hold, errors.New("invalid reboot hold")
	}
	return hold, nil
}

func (a *Agent) rebootHealth() api.HostHealth {
	if a.cfg.StateDir == "" {
		return api.HostHealth{}
	}
	return observeReboot(a.cfg.StateDir, "/run/reboot-required", "/proc/sys/kernel/random/boot_id")
}

func observeReboot(dir, marker, bootFile string) api.HostHealth {
	_, markerErr := os.Lstat(marker)
	path := filepath.Join(dir, rebootHoldFile)
	hold, err := readRebootHold(path)
	if os.IsNotExist(markerErr) && os.IsNotExist(err) {
		return api.HostHealth{}
	}
	data, bootErr := os.ReadFile(bootFile)
	boot := strings.TrimSpace(string(data))
	required := markerErr == nil
	ready := false
	if required && bootErr == nil && boot != "" && (os.IsNotExist(err) || (err == nil && hold.VerifiedBoot != "")) {
		// Remember the boot before reporting a hold. Retries on this boot
		// cannot replace an outstanding checkpoint.
		if err := writeJSON0600(path, rebootHold{PendingBoot: boot}); err != nil {
			return api.HostHealth{RebootRequired: &required, PostRebootReady: &ready}
		}
	}
	if os.IsNotExist(markerErr) && err == nil && bootErr == nil && boot != "" {
		ready = hold.VerifiedBoot == boot
	}
	return api.HostHealth{RebootRequired: &required, PostRebootReady: &ready}
}

// ConfirmPostRebootReadiness records clearance after the installer has
// verified the running installation and fresh Plane readiness.
func ConfirmPostRebootReadiness(dir, boot string) error {
	return confirmPostRebootReadiness(dir, boot, "/run/reboot-required")
}

func confirmPostRebootReadiness(dir, boot, marker string) error {
	path := filepath.Join(dir, rebootHoldFile)
	hold, err := readRebootHold(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		return errors.New("OS reboot requirement must be resolved before resume")
	}
	if boot == "" || boot == hold.PendingBoot {
		return errors.New("reboot hold requires a different verified boot")
	}
	hold.VerifiedBoot = boot
	return writeJSON0600(path, hold)
}

// Isolated managed Halo profiles don't use the default installer state path.
// Recheck their local runtime and require fresh certification from their own
// Plane after a changed boot before clearing the profile's hold.
func (a *Agent) verifyManagedReboot(ctx context.Context, reboot api.HostHealth, health *api.HostHealth, boot, environment string, hb api.HeartbeatResponse) {
	if !rebootHeld(reboot) || reboot.RebootRequired == nil || *reboot.RebootRequired ||
		a.cfg.ManagedDeviceID == "" || !strings.HasPrefix(strings.ToLower(a.cfg.HostName), "halo") ||
		a.maintenanceHeld() || a.cfg.Validate() != nil || boot == "" || environment == "" ||
		hb.DeviceID != a.state.DeviceID || hb.EffectiveCertificationState() != api.PathBGreen ||
		health.LeaseContainerCount == nil || *health.LeaseContainerCount != 0 ||
		a.localLease() != nil {
		return
	}
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	facts := hardware.Detect(probe).Facts
	if probe.Err() != nil || !facts.Vulkan || facts.StrixHaloGTTFreeBytes <= 0 {
		return
	}
	if err := ConfirmPostRebootReadiness(a.cfg.StateDir, boot); err != nil {
		a.log.Warn("Post-reboot readiness remains held", "err", err)
	}
}
