package visorbridge

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlanBridgeInjectsOnlyConfiguredScope(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.config.Tenant = uuid.NewString()
	b.config.Device = uuid.NewString()
	p := &PromptConfig{PreviewBinding: PreviewBinding{Bot: uuid.NewString(), Assignment: uuid.NewString(), Session: uuid.NewString(), Organization: uuid.NewString()}, Workspace: "/project", Socket: "/private/socket", Class: "coding", Destination: "configured", MaxOutput: 128}
	b.config.MachinePrompt = p
	b.credential = func(context.Context) (string, error) { return "hm_msi_private", nil }
	calls := 0
	b.command = func(_ context.Context, action string, raw []byte, limit int) ([]byte, error) {
		calls++
		var input map[string]any
		json.Unmarshal(raw, &input)
		target := input["input"].(map[string]any)
		if action != "continue-plan" || target["destination"] != "configured" || input["credential"] != "hm_msi_private" {
			t.Fatal(input)
		}
		return []byte(`{"needs_input":[]}`), nil
	}
	for _, body := range []string{`{"workspace":"/project","plan":{}}`, `{"workspace":"/other","plan":{}}`, `{"workspace":"/project","plan":{},"destination":"evil"}`} {
		r := httptest.NewRequest("POST", "/continue-plan", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "hm_msi") {
			t.Fatal("credential returned")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
