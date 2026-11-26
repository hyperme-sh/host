//go:build linux

package installer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
	"github.com/FyberLabs/hypermesh-host/internal/hardware"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
	"github.com/FyberLabs/hypermesh-host/internal/telem"
)

const nativeAutomaticHalo = true

func runHaloNativeCertification(ctx context.Context, args []string, out, diagnostic io.Writer, planning bool) int {
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		fmt.Fprintln(diagnostic, "native Halo certification requires root on Linux amd64")
		return 1
	}
	if _, managed := nativeAutomatic(ctx); !managed {
		if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
			fmt.Fprintln(diagnostic, "cannot set trusted system tool path")
			return 1
		}
	}
	return runNativeCertification(ctx, args, out, diagnostic, planning, nativeDeps{
		installation: haloNativeInstallation,
		stateDir:     haloState,
		lock:         lockSetupState,
		backend:      "vulkan",
		inventory: func(ctx context.Context) (string, string, error) {
			snapshot, err := telem.Default().Collect(ctx)
			if err != nil {
				return "", "", err
			}
			return snapshot.EnvironmentHash, hardware.Detect(ctx).Fingerprint, nil
		},
		remote: func(base, tenant string) (nativeRemote, error) {
			client, err := hostregistration.New(base, tenant)
			if err == nil {
				client.SetMachineIdentity(filepath.Join(haloState, "machine-identity.json"))
			}
			return client, err
		},
		measure: certmeasure.Run,
	})
}

func readHaloNativePlan(path, digest string) (agentInstallPlan, error) {
	var plan agentInstallPlan
	if path == "" {
		directory := filepath.Join(haloState, "provision")
		if err := secureSetupDirectory(directory, false); err != nil {
			return plan, err
		}
		path = filepath.Join(directory, "agent.json")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return plan, fmt.Errorf("Halo agent plan requires a canonical absolute path")
	}
	// Separately installed plans can be operator-readable. Their contents must
	// still match both the approved digest and the private registration journal.
	if err := guidedRead(path, &plan, false); err != nil {
		return plan, err
	}
	if plan.SHA256 != digest || agentPlanDigest(plan) != digest {
		return plan, fmt.Errorf("installed Halo plan differs from the approved digest")
	}
	return plan, nil
}

// Match kernel payloads and kernel meta packages. Firmware, Mesa, Vulkan,
// libdrm, and unrelated Linux packages retain the registration checks.
var haloKernelPackage = regexp.MustCompile(
	`^linux-(?:(?:libc-dev|perf|tools-common)|(?:headers|image-unsigned|image|main-modules-v4l2loopback|main-modules-zfs|modules-extra|modules|tools)-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+(?:-[a-z0-9-]+)?|(?:(?:headers|image|modules|tools)-)?(?:generic|virtual|lowlatency|oem)(?:-hwe-[0-9]+\.[0-9]+(?:-edge)?)?)$`,
)

func haloCertificationPackages(plan SetupPlan, installed map[string]string) ([]PackageChange, error) {
	keep := func(packages []PackageChange) []PackageChange {
		var retained []PackageChange
		for _, pkg := range packages {
			if !haloKernelPackage.MatchString(packageBase(pkg.Name)) {
				retained = append(retained, pkg)
			}
		}
		return retained
	}
	plan.Platform.ProtectedPackages = keep(plan.Platform.ProtectedPackages)
	// The current certification still checks the network and uses the existing
	// enrollment. Allow Ubuntu NetworkManager package updates without waiving
	// the requirement that previously installed packages remain present.
	for i, pkg := range plan.Platform.ProtectedPackages {
		base := packageBase(pkg.Name)
		if version := installed[pkg.Name]; version != "" &&
			(base == "network-manager" || strings.HasPrefix(base, "network-manager-")) {
			plan.Platform.ProtectedPackages[i].To = version
		}
	}
	plan.Packages = keep(plan.Packages)
	runtimePackages := make(map[string]string, len(installed))
	for name, version := range installed {
		if !haloKernelPackage.MatchString(packageBase(name)) {
			runtimePackages[name] = version
		}
	}
	return registrationPackages(plan, runtimePackages)
}

func haloNativeInstallation(_ context.Context, digest, agentPlanPath string) (nativeInstallation, error) {
	plan, err := readHaloNativePlan(agentPlanPath, digest)
	if err != nil {
		return nativeInstallation{}, err
	}
	var journal registrationJournal
	if err := guidedRead(filepath.Join(haloState, "registration.json"), &journal, true); err != nil {
		return nativeInstallation{}, err
	}
	network, _ := installationNetwork("test")
	if journal.State != "registered-inactive" || validateRegistration(journal, plan, network.Issuer, network.Dashboard, haloClass) != nil {
		return nativeInstallation{}, fmt.Errorf("native certification requires the current inactive Halo TEST registration")
	}

	check := func(ctx context.Context) error {
		if _, managed := nativeAutomatic(ctx); !managed {
			for _, unit := range []string{"hypermesh-halo-test-agent.service", "hypermesh-agent.service", "hypermesh-wg.service"} {
				raw, err := (setupSource{}).output(ctx, "systemctl", "--system", "show", unit, "-p", "ActiveState", "--value")
				state := strings.TrimSpace(string(raw))
				if err != nil || (state != "inactive" && state != "failed") {
					return fmt.Errorf("%s must be inactive for native certification", unit)
				}
			}
		}
		for _, state := range []string{haloState, "/var/lib/hypermesh"} {
			if _, err := os.Lstat(filepath.Join(state, "lease.json")); !os.IsNotExist(err) {
				return fmt.Errorf("reconcile local leases before native Halo certification")
			}
		}
		setup, err := reviewedRegistrationSetup(plan)
		if err != nil {
			return err
		}
		fresh, err := checkRegistrationPreflight(ctx, plan, haloClass, setup, true)
		if err != nil {
			return err
		}
		if err := validateHaloScope(plan, network.Issuer, network.Dashboard, fresh); err != nil {
			return err
		}
		for _, file := range haloProfile(plan, journal) {
			if file.Path != filepath.Join(haloState, "device.json") && file.Path != filepath.Join(haloConfig, "agent.env") {
				continue
			}
			actual, err := readSetupRegular(file.Path, true)
			if err != nil || !bytes.Equal(actual, file.Data) {
				return fmt.Errorf("installed Halo TEST identity or environment differs from the registration")
			}
		}
		return nil
	}
	return nativeInstallation{journal: journal, plane: network.Plane, tenant: plan.TenantID, check: check}, nil
}
