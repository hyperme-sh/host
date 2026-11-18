package visorbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceArgumentsAreBoundToRootConfiguration(t *testing.T) {
	b := &Bridge{config: Config{ClientUID: 1001, ServiceControl: &UserServiceConfig{Executable: "/usr/bin/systemctl", UID: 1001, GID: 1001, Units: []string{"worker.service"}}}}
	binding, err := b.serviceBinding()
	if err != nil {
		t.Fatal(err)
	}
	args := serviceArguments{Verb: "restart", Unit: "worker.service", UID: 1001, Executable: "/usr/bin/systemctl", ExecutableHash: strings.Repeat("a", 64), BindingHash: binding}
	action := func(a serviceArguments) []byte {
		raw, _ := json.Marshal(a)
		sum := sha256.Sum256(raw)
		out, _ := json.Marshal(map[string]any{"operation": "service_restart", "target": "worker.service", "arguments_json": string(raw), "arguments_sha256": hex.EncodeToString(sum[:]), "limits": map[string]any{"max_bytes": 10, "timeout_seconds": 2}})
		return out
	}
	if _, err = b.serviceCall(action(args), args.ExecutableHash); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*serviceArguments){func(a *serviceArguments) { a.UID = 0 }, func(a *serviceArguments) { a.Unit = "other.service" }, func(a *serviceArguments) { a.Executable = "/bin/sh" }, func(a *serviceArguments) { a.Verb = "stop" }, func(a *serviceArguments) { a.BindingHash = strings.Repeat("b", 64) }} {
		changed := args
		change(&changed)
		if _, err = b.serviceCall(action(changed), args.ExecutableHash); err == nil {
			t.Fatal("accepted changed binding")
		}
	}
	if _, err = b.serviceCall(action(args), strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted changed executable")
	}
	b.config.ServiceControl.UID = 0
	if _, err = b.serviceBinding(); err == nil {
		t.Fatal("accepted root")
	}
}
