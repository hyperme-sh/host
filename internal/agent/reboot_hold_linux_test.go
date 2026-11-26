package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/api"
)

func TestRebootHoldRequiresVerifiedChangedBoot(t *testing.T) {
	dir := t.TempDir()
	marker, boot := filepath.Join(dir, "required"), filepath.Join(dir, "boot")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(boot, "original-boot")
	if rebootHeld(observeReboot(dir, marker, boot)) {
		t.Fatal("unexpected hold before the OS marker")
	}
	write(marker, "")
	report := observeReboot(dir, marker, boot)
	raw, _ := json.Marshal(report)
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || fields["reboot_required"] != true || fields["post_reboot_ready"] != false {
		t.Fatalf("unexpected heartbeat fields: %s", raw)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := confirmPostRebootReadiness(dir, "original-boot", marker); err == nil {
		t.Fatal("cleared hold on the original boot")
	}
	write(boot, "new-boot")
	if !rebootHeld(observeReboot(dir, marker, boot)) {
		t.Fatal("cleared hold before readiness verification")
	}
	if err := confirmPostRebootReadiness(dir, "new-boot", marker); err != nil {
		t.Fatal(err)
	}
	report = observeReboot(dir, marker, boot)
	if rebootHeld(report) || report.PostRebootReady == nil || !*report.PostRebootReady {
		t.Fatal("verified reboot did not clear the hold")
	}
	write(marker, "")
	if !rebootHeld(observeReboot(dir, marker, boot)) {
		t.Fatal("a new OS reboot requirement did not reinstate the hold")
	}
}

func TestPendingRebootHoldBlocksLeaseStartBeforeRuntime(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON0600(filepath.Join(dir, rebootHoldFile), rebootHold{PendingBoot: "earlier-boot"}); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{cfg: Config{StateDir: dir}}
	result := agent.leaseStart(context.Background(), api.Job{LeaseID: "new-lease"})
	if result.Passed || result.Reason != "reboot readiness required" {
		t.Fatalf("lease start was not held: %+v", result)
	}
}
