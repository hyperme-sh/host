package visorbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPermissionPreviewKeepsCredentialInsideTrustedChild(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.config.Tenant = uuid.NewString()
	b.config.Device = uuid.NewString()
	binding := &PreviewBinding{Bot: uuid.NewString(), Assignment: uuid.NewString(), Session: uuid.NewString(), Organization: uuid.NewString()}
	b.config.PermissionPreview = binding
	b.credential = func(context.Context) (string, error) { return "hm_msi_private", nil }
	calls := 0
	b.command = func(ctx context.Context, action string, raw []byte, limit int) ([]byte, error) {
		calls++
		if action != "permission-preview" || limit != 16384 {
			t.Fatal(action, limit)
		}
		var envelope map[string]json.RawMessage
		json.Unmarshal(raw, &envelope)
		if string(envelope["credential"]) != `"hm_msi_private"` {
			t.Fatal("missing private credential")
		}
		var preview map[string]any
		json.Unmarshal(envelope["preview"], &preview)
		if preview["device_id"] != b.config.Device || preview["bot_id"] != binding.Bot {
			t.Fatal("configured scope missing")
		}
		return json.Marshal(map[string]any{"version": 1, "request_id": preview["request_id"], "preview_only": true, "identity": map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}, "decision": "advisory"})
	}
	body := []byte(`{"project":"/project","template_version":1,"template":[],"action":{}}`)
	for _, uid := range []uint32{1001, 1002, 0} {
		r := httptest.NewRequest("POST", "/permission-preview", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if uid == 1001 && w.Code != 200 || uid != 1001 && w.Code == 200 {
			t.Fatal(uid, w.Code)
		}
		if strings.Contains(w.Body.String(), "hm_msi_") {
			t.Fatal("credential escaped")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	// A caller cannot replace the device binding in its request.
	r := httptest.NewRequest("POST", "/permission-preview", strings.NewReader(`{"device_id":"other","project":"/project","template_version":1,"template":[],"action":{}}`))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	if w.Code == 200 || calls != 1 {
		t.Fatal("caller scope accepted")
	}
}

func TestReadReviewBindsProjectAndKeepsCredentialPrivate(t *testing.T) {
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
		if action != "permission-read-review" || limit != 16384 {
			t.Fatal(action, limit)
		}
		var envelope map[string]json.RawMessage
		json.Unmarshal(raw, &envelope)
		if string(envelope["credential"]) != `"hm_msi_private"` {
			t.Fatal("missing private credential")
		}
		var preview map[string]any
		json.Unmarshal(envelope["preview"], &preview)
		if preview["device_id"] != b.config.Device || preview["bot_id"] != binding.Bot {
			t.Fatal("configured scope missing")
		}
		return json.Marshal(map[string]any{"version": 1, "request_id": preview["request_id"], "preview_only": false, "identity": map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}, "decision": "advisory"})
	}
	body := []byte(`{"request_id":"` + uuid.NewString() + `","project":"/project","template_version":1,"template":[],"action":{}}`)
	for _, uid := range []uint32{1001, 1002, 0} {
		r := httptest.NewRequest("POST", "/permission-read-review", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if uid == 1001 && w.Code != 200 || uid != 1001 && w.Code == 200 {
			t.Fatal(uid, w.Code)
		}
		if strings.Contains(w.Body.String(), "hm_msi_") {
			t.Fatal("credential escaped")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	// A caller cannot replace the device binding in its request.
	r := httptest.NewRequest("POST", "/permission-read-review", strings.NewReader(`{"device_id":"other","project":"/project","template_version":1,"template":[],"action":{}}`))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	if w.Code == 200 || calls != 1 {
		t.Fatal("caller scope accepted")
	}

	for _, project := range []string{"/other", "/project/../other"} {
		bad := strings.Replace(string(body), `"/project"`, `"`+project+`"`, 1)
		r := httptest.NewRequest("POST", "/permission-read-review", strings.NewReader(bad))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if w.Code == 200 || calls != 1 {
			t.Fatal("project override accepted")
		}
	}
}

func TestTypedReviewBindsProjectAndKeepsCredentialPrivate(t *testing.T) {
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
		if action != "permission-action-review" || limit != 16384 {
			t.Fatal(action, limit)
		}
		var envelope map[string]json.RawMessage
		json.Unmarshal(raw, &envelope)
		if string(envelope["credential"]) != `"hm_msi_private"` {
			t.Fatal("missing private credential")
		}
		var preview map[string]any
		json.Unmarshal(envelope["preview"], &preview)
		if preview["device_id"] != b.config.Device || preview["bot_id"] != binding.Bot {
			t.Fatal("configured scope missing")
		}
		return json.Marshal(map[string]any{"version": 1, "request_id": preview["request_id"], "preview_only": false, "identity": map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}, "decision": "advisory"})
	}
	body := []byte(`{"request_id":"` + uuid.NewString() + `","project":"/project","template_version":1,"template":[],"action":{}}`)
	for _, uid := range []uint32{1001, 1002, 0} {
		r := httptest.NewRequest("POST", "/permission-action-review", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if uid == 1001 && w.Code != 200 || uid != 1001 && w.Code == 200 {
			t.Fatal(uid, w.Code)
		}
		if strings.Contains(w.Body.String(), "hm_msi_") {
			t.Fatal("credential escaped")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	// A caller cannot replace the device binding in its request.
	r := httptest.NewRequest("POST", "/permission-action-review", strings.NewReader(`{"device_id":"other","project":"/project","template_version":1,"template":[],"action":{}}`))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	if w.Code == 200 || calls != 1 {
		t.Fatal("caller scope accepted")
	}

	for _, project := range []string{"/other", "/project/../other"} {
		bad := strings.Replace(string(body), `"/project"`, `"`+project+`"`, 1)
		r := httptest.NewRequest("POST", "/permission-action-review", strings.NewReader(bad))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if w.Code == 200 || calls != 1 {
			t.Fatal("project override accepted")
		}
	}
}

func TestReadAdmissionBindsProjectAndKeepsCredentialPrivate(t *testing.T) {
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
		if action != "permission-read-admit" || limit != 16384 {
			t.Fatal(action, limit)
		}
		var envelope map[string]json.RawMessage
		json.Unmarshal(raw, &envelope)
		if string(envelope["credential"]) != `"hm_msi_private"` {
			t.Fatal("missing private credential")
		}
		var preview map[string]any
		json.Unmarshal(envelope["preview"], &preview)
		if preview["device_id"] != b.config.Device || preview["bot_id"] != binding.Bot {
			t.Fatal("configured scope missing")
		}
		return json.Marshal(map[string]any{"version": 1, "request_id": preview["request_id"], "preview_only": false, "identity": map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}, "decision": "advisory"})
	}
	body := []byte(`{"request_id":"` + uuid.NewString() + `","project":"/project","template_version":1,"template":[],"action":{}}`)
	for _, uid := range []uint32{1001, 1002, 0} {
		r := httptest.NewRequest("POST", "/permission-read-admit", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if uid == 1001 && w.Code != 200 || uid != 1001 && w.Code == 200 {
			t.Fatal(uid, w.Code)
		}
		if strings.Contains(w.Body.String(), "hm_msi_") {
			t.Fatal("credential escaped")
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	// A caller cannot replace the device binding in its request.
	r := httptest.NewRequest("POST", "/permission-read-admit", strings.NewReader(`{"device_id":"other","project":"/project","template_version":1,"template":[],"action":{}}`))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	if w.Code == 200 || calls != 1 {
		t.Fatal("caller scope accepted")
	}

	for _, project := range []string{"/other", "/project/../other"} {
		bad := strings.Replace(string(body), `"/project"`, `"`+project+`"`, 1)
		r := httptest.NewRequest("POST", "/permission-read-admit", strings.NewReader(bad))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(1001)))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		if w.Code == 200 || calls != 1 {
			t.Fatal("project override accepted")
		}
	}
}
