//go:build linux

package nativecrash

// This contract is selected only by Infra's declared disposable systemd VM.
// It substitutes the model with a fixed crashing process and the registration
// authority with an in-memory scoped fact. Cleanup, Docker, SDK, reducer,
// sanitized sender and GlitchTip are real owners in the isolated composition.
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/FyberLabs/hypermesh-host/internal/hostcrash"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestContainerCrashNightly(t *testing.T) {
	if os.Getenv("HYPERMESH_HOST_CONTAINER_NIGHTLY") != "1" {
		t.Skip("declared scheduled VM only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root fixture unavailable")
	}
	const fixture = "/run/host-crash-fixture"
	var config struct {
		Tenant  string `json:"tenant"`
		Device  string `json:"device"`
		DSN     string `json:"dsn"`
		Broker  string `json:"broker"`
		Project int    `json:"project"`
	}
	bytes, err := os.ReadFile(filepath.Join(fixture, "client.json"))
	if err != nil || json.Unmarshal(bytes, &config) != nil {
		t.Fatal("private fixture config unavailable")
	}
	destination, err := hostcrash.ParseDestination(config.DSN, config.Broker)
	if err != nil {
		t.Fatal("fixture destination invalid")
	}
	statePath := filepath.Join(fixture, "device.json")
	docker := func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var eventID string
	var sendError error
	reports := 0
	manager := NewContainerManager(statePath, func(report Report) {
		reports++
		root, err := root()
		if err != nil {
			sendError = ErrUnavailable
			return
		}
		entries, err := os.ReadDir(filepath.Join(root, "crash-runs"))
		if err != nil || len(entries) != 0 {
			sendError = ErrUnavailable
			return
		}
		event, err := hostcrash.NewNativeEvent(config.Tenant, report.Captured, report.Code)
		if err != nil {
			sendError = err
			return
		}
		eventID = event.ID
		sendError = destination.Send(ctx, config.Tenant, config.Device, event, func(_ context.Context, event hostcrash.Event) ([]byte, error) {
			return json.Marshal(map[string]any{"version": 1, "registered": true, "tenant": config.Tenant, "subject": "isolated-registration-stub", "device": config.Device, "project": config.Project, "event_id": event.ID, "captured_at": event.Captured, "payload_sha256": event.Hash})
		})
	})
	outcomes := map[string]string{"guarded-native-crash": "blocked", "sanitized-send-after-purge": "blocked", "cleanup-service-loss-refuses": "blocked", "kernel-storage-bound": "blocked"}
	defer func() {
		value := map[string]any{"cases": outcomes, "event_id": eventID}
		raw, _ := json.Marshal(value)
		_ = os.WriteFile(filepath.Join(fixture, "result.json"), raw, 0600)
	}()
	launch := func(name string) (string, error) {
		args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--ulimit", "core=0", "--log-driver", "none", "--tmpfs", "/tmp:rw,nosuid,size=16m", "--entrypoint", "/bin/sh", "host-crash-fixture:test", "-c", "exec /opt/host-crash-tests/crash-fixture"}
		out, err := manager.Start(ctx, docker, args)
		return strings.TrimSpace(string(out)), err
	}
	stop := func(id string) { _, _ = docker(ctx, "stop", "-t", "2", id); _, _ = docker(ctx, "rm", "-f", id) }
	id, err := launch("host-crash-success")
	if err != nil {
		outcomes["guarded-native-crash"] = "failed"
		t.Fatal("guarded launch failed")
	}
	defer stop(id)
	manager.mu.Lock()
	active := manager.sessions[id] != nil
	manager.mu.Unlock()
	if !active {
		outcomes["guarded-native-crash"] = "failed"
		t.Fatal("capture preparation fell back")
	}
	// Wait for the SDK's real handler process, not just a container start.
	ready := false
	for i := 0; i < 100; i++ {
		out, e := docker(ctx, "top", id, "-eo", "comm")
		if e == nil && strings.Contains(string(out), "crashpad") {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		outcomes["guarded-native-crash"] = "failed"
		t.Fatal("native handler missing")
	}
	if _, err = docker(ctx, "kill", "--signal=SEGV", id); err != nil {
		t.Fatal("fixture crash failed")
	}
	out, err := docker(ctx, "wait", id)
	if err != nil {
		t.Fatal("fixture exit missing")
	}
	status, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	if status == 0 {
		t.Fatal("fixture did not crash")
	}
	stop(id)
	if manager.Finish(ctx, id, true) != nil || reports != 1 {
		outcomes["guarded-native-crash"] = "failed"
		t.Fatal("fixed native report missing")
	}
	outcomes["guarded-native-crash"] = "passed"
	if sendError != nil || eventID == "" {
		outcomes["sanitized-send-after-purge"] = "failed"
		t.Fatal("sanitized destination refused")
	}
	outcomes["sanitized-send-after-purge"] = "passed"
	// A new run must lose authority when the real OS-managed service stops.
	second, err := launch("host-crash-refusal")
	if err != nil {
		outcomes["cleanup-service-loss-refuses"] = "failed"
		t.Fatal("second guarded launch failed")
	}
	defer stop(second)
	filled, fillError := docker(ctx, "exec", second, "dd", "if=/dev/zero", "of=/var/lib/hypermesh-crash/database/quota-probe", "bs=1048576", "count=161", "status=none")
	if fillError == nil || !strings.Contains(string(filled), "No space left on device") {
		outcomes["kernel-storage-bound"] = "failed"
		t.Fatal("kernel raw storage cap not enforced")
	}
	outcomes["kernel-storage-bound"] = "passed"
	if exec.CommandContext(ctx, "systemctl", "stop", "hypermesh-host-crash-retention.service").Run() != nil {
		t.Fatal("service stop failed")
	}
	time.Sleep(time.Second)
	_, _ = docker(ctx, "kill", "--signal=SEGV", second)
	_, _ = docker(ctx, "wait", second)
	stop(second)
	_ = manager.Finish(ctx, second, true)
	if reports != 1 {
		outcomes["cleanup-service-loss-refuses"] = "failed"
		t.Fatal("report sent after loss of cleanup")
	}
	outcomes["cleanup-service-loss-refuses"] = "passed"
	fmt.Fprintln(os.Stdout, "Host container nightly contract completed")
}
