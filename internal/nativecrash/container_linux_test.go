//go:build linux

package nativecrash

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestContainerMountsPreserveJailAndKeepAuthorityPrivate(t *testing.T) {
	base := []string{"run", "-d", "--network", "hypermesh-workload", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--log-driver", "none", "--ulimit", "core=0", "--entrypoint", "/bin/sh", "ghcr.io/example/worker:test", "-c", "exec llama-server --alias \"$MODEL\""}
	mounts := containerMounts{Database: "/private/run/database", Control: "/private/control"}
	got, err := containerArgs(base, mounts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[9:len(got)-1], base[1:len(base)-1]) {
		t.Fatalf("original jail/model options changed: %v", got)
	}
	joined := strings.Join(got, " ")
	for _, bad := range []string{"--privileged", "--pid=host", "device.json", "docker.sock"} {
		if strings.Contains(joined, bad) {
			t.Fatal(bad)
		}
	}
	if !strings.Contains(joined, mounts.Control+":/run/hypermesh-crash:ro") || !strings.HasSuffix(got[len(got)-1], base[len(base)-1]) {
		t.Fatal("mount/script contract")
	}
	for _, bad := range []string{"relative", "/root/path:rw", "/root/path\nother", "/root/path,other"} {
		mounts.Control = bad
		if _, err := containerArgs(base, mounts); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
func TestUnavailablePreparationFallsBackBeforeDockerOnly(t *testing.T) {
	manager := NewContainerManager("/nonexistent/device.json", nil)
	args := []string{"run", "original"}
	calls := 0
	out, err := manager.Start(context.Background(), func(_ context.Context, got ...string) ([]byte, error) {
		calls++
		if !reflect.DeepEqual(got, args) {
			t.Fatal(got)
		}
		return []byte("normal"), nil
	}, args)
	if err != nil || string(out) != "normal" || calls != 1 {
		t.Fatal("no-capture fallback changed")
	}
	if err := manager.Finish(context.Background(), "unknown", true); err != nil {
		t.Fatal(err)
	}
}

func TestContainerIDConsumedBeforePublicControlBinding(t *testing.T) {
	control := t.TempDir()
	path := filepath.Join(control, "docker.cid")
	want := strings.Repeat("a", 64)
	for _, value := range []string{want + "\n", "invalid"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		id, err := consumeContainerID(path)
		if value == "invalid" {
			if err == nil || id != "" {
				t.Fatal("invalid identity accepted")
			}
		} else if err != nil || id != want {
			t.Fatal("created identity lost")
		}
		entries, err := os.ReadDir(control)
		if err != nil || len(entries) != 0 {
			t.Fatal("control directory occupied before helper binding")
		}
	}
	if _, err := consumeContainerID(path); err == nil {
		t.Fatal("missing identity accepted")
	}
}
