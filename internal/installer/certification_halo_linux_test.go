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
