package visorbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMachinePromptKeepsOwnerBytesAndConfiguredRoute(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.config.Tenant = uuid.NewString()
	b.config.Device = uuid.NewString()
	p := &PromptConfig{PreviewBinding: PreviewBinding{Bot: uuid.NewString(), Assignment: uuid.NewString(), Session: uuid.NewString(), Organization: uuid.NewString()}, Workspace: "/project", Socket: "/private/conductor.sock", Class: "coding", Destination: "configured", MaxOutput: 1024}
	b.config.MachinePrompt = p
	b.credential = func(context.Context) (string, error) { return "hm_msi_private", nil }
	body := b.machineBinding()
	body["task_id"] = uuid.NewString()
	body["operation_id"] = uuid.NewString()
	body["class"] = p.Class
	body["destination"] = p.Destination
	body["max_output_tokens"] = p.MaxOutput
	body["prompt"] = strings.Repeat("\n", 50000)
	raw, _ := json.MarshalIndent(body, "", " ")
	calls := 0
	b.command = func(_ context.Context, action string, input []byte, limit int) ([]byte, error) {
		calls++
		var envelope map[string]string
		if json.Unmarshal(input, &envelope) != nil {
			t.Fatal("invalid envelope")
		}
		original, e := base64.StdEncoding.DecodeString(envelope["submission_base64"])
		if e != nil || string(original) != string(raw) || envelope["credential"] != "hm_msi_private" || action != "machine-prompt" {
			t.Fatal("owner bytes or credential changed")
		}
		return []byte(`{"choices":[{"message":{"content":"answer"}}]}`), nil
	}
	request := func(input string, uid uint32) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/machine-prompt", strings.NewReader(input))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request(string(raw), 1001); w.Code != 200 || strings.Contains(w.Body.String(), "hm_msi_") {
		t.Fatal(w.Code)
	}
	if request(string(raw), 1002).Code == 200 {
		t.Fatal("other user accepted")
	}
	body["destination"] = "attacker"
	changed, _ := json.Marshal(body)
	if request(string(changed), 1001).Code == 200 || calls != 1 {
		t.Fatal("route replacement accepted")
	}
}
