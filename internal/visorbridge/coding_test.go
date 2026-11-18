package visorbridge

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCodingBridgeUsesOnlyConfiguredTarget(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.config.Tenant = uuid.NewString()
	b.config.Device = uuid.NewString()
	p := &PromptConfig{PreviewBinding: PreviewBinding{Bot: uuid.NewString(), Assignment: uuid.NewString(), Session: uuid.NewString(), Organization: uuid.NewString()}, Workspace: "/project", Socket: "/private/conductor.sock", Class: "coding", Destination: "configured", MaxOutput: 1024}
	b.config.MachinePrompt = p
	b.credential = func(context.Context) (string, error) { return "hm_msi_private", nil }
	calls := 0
	b.command = func(ctx context.Context, action string, raw []byte, limit int) ([]byte, error) {
		calls++
		var input map[string]any
		json.Unmarshal(raw, &input)
		target := input["target"].(map[string]any)
		if action != "coding-run" || input["credential"] != "hm_msi_private" || target["workspace"] != "/project" || target["destination"] != "configured" || target["device_id"] != b.config.Device {
			t.Fatal("wrong target")
		}
		return []byte(`{"version":1,"state":"idle"}`), nil
	}
	request := func(body string, uid uint32) int {
		r := httptest.NewRequest("POST", "/coding-run", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := &promptRecorder{ResponseRecorder: httptest.NewRecorder()}
		b.Handler().ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "hm_msi") {
			t.Fatal("credential exposed")
		}
		return w.Code
	}
	if request("{}", 1001) != 200 || calls != 1 {
		t.Fatal("trusted request refused")
	}
	if request(`{"workspace":"/other"}`, 1001) == 200 || request("{}", 1002) == 200 || calls != 1 {
		t.Fatal("caller-controlled target or peer accepted")
	}
}
