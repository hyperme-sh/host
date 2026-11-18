//go:build linux

package visorbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestServiceCommandDropsPrivilegeAndFixesArguments(t *testing.T) {
	c := &UserServiceConfig{UID: 1001, GID: 1002}
	cmd := serviceCommand(context.Background(), c, "worker.service", nil)
	if !reflect.DeepEqual(cmd.Args, []string{"/proc/self/fd/3", "--user", "--no-ask-password", "restart", "--", "worker.service"}) {
		t.Fatal(cmd.Args)
	}
	credentials := cmd.SysProcAttr.Credential
	if credentials.Uid != 1001 || credentials.Gid != 1002 || len(credentials.Groups) != 0 {
		t.Fatal(credentials)
	}
	if len(cmd.Env) != 5 || cmd.Env[2] != "HOME=/nonexistent" || cmd.Env[4] != "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus" {
		t.Fatal(cmd.Env)
	}
	b := &Bridge{}
	for _, review := range []string{`{"reserved":false,"permitted":true}`, `{"reserved":true,"permitted":true,"expires_at":1}`} {
		if _, err := b.restartService(context.Background(), []byte(`{}`), []byte(review)); err == nil {
			t.Fatal("executed without current admission")
		}
	}
}

func TestServiceDeadlineUsesShorterLimit(t *testing.T) {
	now := time.Unix(100, 0)
	if got := serviceDeadline(110, 2, now); !got.Equal(time.Unix(102, 0)) {
		t.Fatal(got)
	}
	if got := serviceDeadline(101, 2, now); !got.Equal(time.Unix(101, 0)) {
		t.Fatal(got)
	}
}

func TestNamedServiceExecutorRequiresCurrentBoundAdmission(t *testing.T) {
	b := &Bridge{config: Config{ClientUID: 1001, ServiceControl: &UserServiceConfig{Executable: "/usr/bin/systemctl", UID: 1001, GID: 1001, Units: []string{"worker.service"}}}}
	binding, _ := b.serviceBinding()
	hash := strings.Repeat("a", 64)
	args, _ := json.Marshal(serviceArguments{Verb: "restart", Unit: "worker.service", UID: 1001, Executable: "/usr/bin/systemctl", ExecutableHash: hash, BindingHash: binding})
	sum := sha256.Sum256(args)
	action, _ := json.Marshal(map[string]any{"operation": "service_restart", "target": "worker.service", "arguments_json": string(args), "arguments_sha256": hex.EncodeToString(sum[:]), "limits": map[string]any{"max_bytes": 10, "timeout_seconds": 2}})
	review := map[string]any{"reserved": true, "dispatch_admitted": true, "permitted": true, "expires_at": float64(time.Now().UnixNano())/1e9 + 9, "action": json.RawMessage(action)}
	calls := 0
	open := func() (*os.File, string, error) { f, err := os.Open(os.DevNull); return f, hash, err }
	namedExecutor := func(cmd *exec.Cmd) error {
		calls++
		if cmd.Args[len(cmd.Args)-1] != "worker.service" || cmd.SysProcAttr.Credential.Uid != 1001 {
			t.Fatal(cmd.Args)
		}
		return nil
	}
	raw, _ := json.Marshal(review)
	output, err := b.restartServiceWith(context.Background(), action, raw, open, namedExecutor)
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	var result map[string]any
	json.Unmarshal(output, &result)
	if result["completed"] != true {
		t.Fatal(result)
	}
	review["dispatch_admitted"] = false
	raw, _ = json.Marshal(review)
	if _, err = b.restartServiceWith(context.Background(), action, raw, open, namedExecutor); err == nil || calls != 1 {
		t.Fatal("legacy reservation executed without owner admission")
	}
	review["dispatch_admitted"] = true
	review["reserved"] = false
	raw, _ = json.Marshal(review)
	if _, err = b.restartServiceWith(context.Background(), action, raw, open, namedExecutor); err == nil || calls != 1 {
		t.Fatal("unreserved execution")
	}
	review["reserved"] = true
	raw, _ = json.Marshal(review)
	changed := func() (*os.File, string, error) {
		f, err := os.Open(os.DevNull)
		return f, strings.Repeat("b", 64), err
	}
	if _, err = b.restartServiceWith(context.Background(), action, raw, changed, namedExecutor); err == nil || calls != 1 {
		t.Fatal("changed executable executed")
	}
}
