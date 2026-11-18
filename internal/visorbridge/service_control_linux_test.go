//go:build linux

package visorbridge

import (
	"context"
	"reflect"
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
