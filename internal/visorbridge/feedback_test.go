package visorbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const feedbackTenant = "11111111-1111-4111-8111-111111111111"
const feedbackDevice = "22222222-2222-4222-8222-222222222222"

func feedbackToken(id string, now time.Time, change func(map[string]any)) feedbackGrant {
	claims := map[string]any{"iss": "https://plane.example.test", "aud": "hypermesh-feedback-v1", "sub": feedbackTenant, "tenant_id": feedbackTenant, "device_id": feedbackDevice, "jti": id, "iat": now.Unix(), "exp": now.Unix() + 60, "token_use": "native-feedback-v1"}
	if change != nil {
		change(claims)
	}
	payload, _ := json.Marshal(claims)
	encode := base64.RawURLEncoding.EncodeToString
	return feedbackGrant{1, "hm_feedback_" + encode([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + encode(payload) + "." + encode(make([]byte, 64)), 60}
}
func feedbackCall(b *Bridge, uid uint32, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	return w
}
func TestFeedbackGrantCustodyAndLocalAuthority(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	calls, credentials := 0, 0
	status := 200
	responseOverride := ""
	seenIDs := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/hypermesh/agent/feedback/grant" || r.Header.Get("Authorization") != "Bearer hm_msi_private" || r.Header.Get("X-Tenant-ID") != feedbackTenant {
			t.Error("wrong Plane authority")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 3 || body["device_id"] != feedbackDevice || body["version"] != float64(1) {
			t.Error("wrong request scope")
		}
		id, _ := body["request_id"].(string)
		if !feedbackID(id) || seenIDs[id] {
			t.Error("request ID not fresh")
		}
		seenIDs[id] = true
		if status != 200 {
			w.Header().Set("Location", "https://other.invalid/")
			w.WriteHeader(status)
			w.Write([]byte("hm_msi_private"))
			return
		}
		if responseOverride != "" {
			w.Write([]byte(responseOverride))
			return
		}
		json.NewEncoder(w).Encode(feedbackToken(id, now, nil))
	}))
	defer server.Close()
	old := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = old }()
	b := &Bridge{config: Config{Base: server.URL, ClientUID: 1000, Tenant: feedbackTenant, Device: feedbackDevice, FeedbackGrants: true}, busy: make(chan struct{}, 1), now: func() time.Time { return now }, credential: func(context.Context) (string, error) { credentials++; return "hm_msi_private", nil }}
	body := `{"version":1,"human_reports_opt_in":true}`
	for _, uid := range []uint32{1001, 0} {
		if feedbackCall(b, uid, "/feedback-grant", body).Code == 200 {
			t.Fatal("wrong local principal accepted")
		}
	}
	for _, raw := range []string{`{}`, `{"version":1,"human_reports_opt_in":false}`, `{"version":1,"human_reports_opt_in":true,"device_id":"override"}`, strings.Repeat("x", 257)} {
		if feedbackCall(b, 1000, "/feedback-grant", raw).Code == 200 {
			t.Fatal("bad opt-in accepted")
		}
	}
	if feedbackCall(b, 1000, "/feedback-grant?override=1", body).Code == 200 {
		t.Fatal("query accepted")
	}
	b.config.FeedbackGrants = false
	if feedbackCall(b, 1000, "/feedback-grant", body).Code == 200 {
		t.Fatal("disabled accepted")
	}
	b.config.FeedbackGrants = true
	b.busy <- struct{}{}
	if feedbackCall(b, 1000, "/feedback-grant", body).Code == 200 {
		t.Fatal("busy accepted")
	}
	<-b.busy
	if calls != 0 || credentials != 0 {
		t.Fatal("refusal touched credentials or network")
	}
	for i := 0; i < 2; i++ {
		r := feedbackCall(b, 1000, "/feedback-grant", body)
		if r.Code != 200 || strings.Contains(r.Body.String(), "hm_msi_") || r.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid response %d", r.Code)
		}
	}
	status = 302
	r := feedbackCall(b, 1000, "/feedback-grant", body)
	if r.Code != 503 || strings.Contains(r.Body.String(), "hm_msi_") || calls != 3 {
		t.Fatal("redirect or upstream secret escaped")
	}
	status = 200
	for _, invalid := range []string{strings.Repeat("x", 4097), `{"version":1,"expires_in":60,"grant":"hm_msi_private"}`, `{"version":1,"expires_in":60,"grant":"hm_feedback_invalid","extra":"private"}`} {
		responseOverride = invalid
		result := feedbackCall(b, 1000, "/feedback-grant", body)
		if result.Code != 503 || strings.Contains(result.Body.String(), "private") {
			t.Fatal("invalid upstream response escaped")
		}
	}
}
func TestFeedbackGrantResponseBindings(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	id := feedbackDevice
	if !validFeedbackGrant(feedbackToken(id, now, nil), feedbackTenant, feedbackDevice, id, now) {
		t.Fatal("valid grant refused")
	}
	for key, value := range map[string]any{"aud": "review", "token_use": "other", "sub": "invalid", "tenant_id": feedbackDevice, "device_id": feedbackTenant, "jti": feedbackTenant, "iat": now.Unix() + 1, "exp": now.Unix() + 61, "iss": "http://wrong.test"} {
		g := feedbackToken(id, now, func(c map[string]any) { c[key] = value })
		if validFeedbackGrant(g, feedbackTenant, feedbackDevice, id, now) {
			t.Fatalf("accepted bad %s", key)
		}
	}
	for _, g := range []feedbackGrant{{1, "hm_msi_private", 60}, {1, "hm_feedback_invalid", 60}, {1, strings.Repeat("x", 4097), 60}, feedbackToken(id, now.Add(-time.Minute), nil)} {
		if validFeedbackGrant(g, feedbackTenant, feedbackDevice, id, now) {
			t.Fatal("invalid grant accepted")
		}
	}
	for _, base := range []string{"http://plane.test", "https://user@plane.test", "https://plane.test/path", "https://plane.test?", "https://plane.test?x=1", "https://plane.test/#x"} {
		if _, err := feedbackOrigin(base); err == nil {
			t.Fatal("invalid origin accepted")
		}
	}
}

func TestStandaloneFeedbackHandlerHasNoOtherAuthority(t *testing.T) {
	calls := 0
	credential := func(context.Context) (string, error) { calls++; return "", fmt.Errorf("fixture stop") }
	handler, err := NewFeedbackHandler("https://plane.test", feedbackTenant, feedbackDevice, credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/feedback-grant", `{}`}, {"POST", "/feedback-grant?override=1", `{}`},
		{"POST", "/feedback-grant?", `{}`}, {"POST", "/crash-register", `{}`},
		{"POST", "/dispatch", `{}`}, {"POST", "/review", `{}`},
		{"POST", "/feedback-grant", `{"version":1,"human_reports_opt_in":false}`},
		{"POST", "/feedback-grant", `{"version":1,"human_reports_opt_in":true,"tenant":"override"}`},
		{"POST", "/feedback-grant", strings.Repeat("x", 257)},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code == 200 || calls != 0 {
			t.Fatal("refused request reached credential", tc.path)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing privacy header")
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/feedback-grant", strings.NewReader(`{"version":1,"human_reports_opt_in":true}`)))
	if calls != 1 || w.Code != 503 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatal("wrong grant-only dispatch")
	}
	if _, err := NewFeedbackHandler("http://plane.test", feedbackTenant, feedbackDevice, credential); err == nil {
		t.Fatal("insecure origin")
	}
	if _, err := NewFeedbackHandler("https://plane.test", feedbackTenant, feedbackDevice, nil); err == nil {
		t.Fatal("missing credential")
	}
}
