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

func TestHaloKernelCleanupKeepsRunningAndRuntimePackagesProtected(t *testing.T) {
	var plan SetupPlan
	plan.Platform.Kernel = "7.3.0-10-generic"
	for _, name := range []string{
		"linux-headers-7.3.0-9", "linux-main-modules-zfs-7.3.0-9-generic",
		"linux-image-unsigned-7.3.0-9-generic",
		"linux-headers-7.3.0-10", "linux-modules-7.3.0-10-generic",
		"linux-generic", "libvulkan1", "mesa-vulkan-drivers",
	} {
		plan.Platform.ProtectedPackages = append(plan.Platform.ProtectedPackages, PackageChange{Name: name, To: "expected"})
	}
	installed := map[string]string{"linux-image-unsigned-7.3.0-9-generic": "changed"}
	got := haloProtectedPackagesAfterKernelCleanup(plan, installed)
	if len(got) != 6 || got[0].Name != "linux-image-unsigned-7.3.0-9-generic" {
		t.Fatalf("unexpected protected package set: %v", got)
	}
	for i, pkg := range plan.Platform.ProtectedPackages[2:] {
		if got[i] != pkg {
			t.Fatalf("protected check lost for %s", pkg.Name)
		}
	}
}
