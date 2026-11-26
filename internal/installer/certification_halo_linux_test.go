//go:build linux

package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadHaloNativePlanAcceptsApprovedSeparateInstallationPlan(t *testing.T) {
	plan := agentInstallPlan{HostName: "HALO495-1"}
	plan.SHA256 = agentPlanDigest(plan)
	path := filepath.Join(t.TempDir(), "separate-install.json")
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := readHaloNativePlan(path, plan.SHA256)
	if err != nil || got.HostName != plan.HostName {
		t.Fatalf("approved plan could not be read: %v", err)
	}
	if _, err := readHaloNativePlan(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted a separately installed plan with the wrong digest")
	}
}

func TestHaloCertificationAllowsKernelUpdatesAndChecksRuntimePackages(t *testing.T) {
	var plan SetupPlan
	plan.Profile = &SetupProfile{ID: "ubuntu-amd-halo-vulkan", RequiredPackages: []string{"docker.io"}}
	plan.Preflight.Hardware.Facts.Arch = "amd64"
	plan.Platform.Kernel = "7.3.0-10-generic"
	for _, name := range []string{
		"linux-image-7.3.0-10-generic", "linux-modules-7.3.0-10-generic",
		"linux-generic-hwe-26.04", "linux-headers-generic-hwe-26.04",
		"linux-libc-dev:amd64", "linux-perf", "linux-tools-common", "network-manager",
		"libvulkan1", "mesa-vulkan-drivers", "linux-firmware",
	} {
		plan.Platform.ProtectedPackages = append(plan.Platform.ProtectedPackages, PackageChange{Name: name, To: "1"})
	}
	installed := map[string]string{
		"docker.io": "1", "libvulkan1": "1", "mesa-vulkan-drivers": "1", "linux-firmware": "1",
		"linux-image-unsigned-8.0.0-11-generic": "2", "linux-modules-8.0.0-11-generic": "2",
		"linux-headers-8.0.0-11": "2", "linux-generic-hwe-26.04": "2",
		"linux-headers-generic-hwe-26.04": "2", "linux-libc-dev:amd64": "2",
		"linux-perf": "2", "linux-tools-common": "2", "network-manager": "2",
		"zfs-zed": "2", "zfsutils-linux": "2",
	}
	if remaining, err := haloCertificationPackages(plan, installed); err != nil || len(remaining) != 0 {
		t.Fatalf("kernel update prevented certification: %v, %v", remaining, err)
	}
	if _, err := registrationPackages(plan, installed); err == nil {
		t.Fatal("the installation package gate accepted changed kernel packages")
	}
	delete(installed, "network-manager")
	if _, err := haloCertificationPackages(plan, installed); err == nil || !strings.Contains(err.Error(), "network-manager") {
		t.Fatalf("removed NetworkManager was accepted: %v", err)
	}
	installed["network-manager"] = "2"
	withZFS := plan
	withZFS.Platform.ProtectedPackages = append(append([]PackageChange(nil), plan.Platform.ProtectedPackages...),
		PackageChange{Name: "zfs-zed", To: "1"})
	if _, err := haloCertificationPackages(withZFS, installed); err == nil || !strings.Contains(err.Error(), "zfs-zed") {
		t.Fatalf("change to a previously protected ZFS package was accepted: %v", err)
	}
	for _, runtimePackage := range []string{"libvulkan1", "mesa-vulkan-drivers", "linux-firmware"} {
		installed[runtimePackage] = "2"
		if _, err := haloCertificationPackages(plan, installed); err == nil || !strings.Contains(err.Error(), runtimePackage) {
			t.Fatalf("runtime drift for %s was not rejected: %v", runtimePackage, err)
		}
		installed[runtimePackage] = "1"
	}
}
