package visorbridge

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDreamUsesConfiguredIdentityAndPrivateCredential(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.config.Tenant = uuid.NewString()
	b.config.Device = uuid.NewString()
	binding := &PreviewBinding{Bot: uuid.NewString(), Assignment: uuid.NewString(), Session: uuid.NewString(), Organization: uuid.NewString()}
	b.config.PermissionPreview = binding
	b.config.MachinePrompt = &PromptConfig{PreviewBinding: *binding, Workspace: "/project", Socket: "/private/conductor.sock", Class: "coding", Destination: "configured", MaxOutput: 1024}
	b.credential = func(context.Context) (string, error) { return "hm_msi_private", nil }
	calls := 0
	b.command = func(ctx context.Context, action string, raw []byte, limit int) ([]byte, error) {
		calls++
		if action != "permission-dream" || limit != 131072 {
			t.Fatal(action, limit)
		}
		var env struct {
			Credential string         `json:"credential"`
			Dream      map[string]any `json:"dream"`
		}
		json.Unmarshal(raw, &env)
		if env.Credential != "hm_msi_private" || env.Dream["tenant_id"] != b.config.Tenant {
			t.Fatal("identity binding missing")
		}
		return json.Marshal(map[string]any{"version": 1, "request_id": env.Dream["request_id"], "project": "/project", "identity": map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}})
	}
	for _, project := range []string{"/other", "/project"} {
		r := httptest.NewRequest("POST", "/permission-dream", strings.NewReader(`{"version":1,"request_id":"`+uuid.NewString()+`","project":"`+project+`","records":[{}]}`))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if (w.Code == 200) != (project == "/project") {
			t.Fatal(w.Code)
		}
		if strings.Contains(w.Body.String(), "hm_msi_") {
			t.Fatal("credential escaped")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
