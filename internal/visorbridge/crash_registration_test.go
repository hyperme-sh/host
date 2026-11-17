package visorbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrashRegistrationBindsMachineAndApprovedHash(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	event, hash := strings.Repeat("a", 32), strings.Repeat("b", 64)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/hypermesh/agent/crashes/grant" {
			if r.Header.Get("Authorization") != "Bearer hm_msi_private" {
				t.Error("missing machine identity at Plane")
			}
			json.NewEncoder(w).Encode(map[string]any{"version": 1, "grant": "hm_crash_scoped"})
			return
		}
		calls++
		if r.URL.Path != "/api/crash/register" || r.Header.Get("Authorization") != "Bearer hm_crash_scoped" {
			t.Error("wrong authority")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("bad body")
		}
		if body["tenant"] != "tenant" || body["device"] != "device" || body["payload_sha256"] != hash {
			t.Error("wrong binding")
		}
		body["subject"] = "owner"
		body["project"] = 7
		body["registered"] = true
		json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	old := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = old }()
	b := &Bridge{config: Config{Base: server.URL, ClientUID: 1000, Tenant: "tenant", Device: "device", CrashRegistrationURL: server.URL + "/api/crash/register"}, now: func() time.Time { return now }, busy: make(chan struct{}, 1), credential: func(context.Context) (string, error) { return "hm_msi_private", nil }}
	claim := crashClaim{1, event, now.Add(-time.Minute).Format(time.RFC3339), hash}
	call := func(raw []byte, uid uint32) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/crash-register", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uid))
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, r)
		return w
	}
	raw, _ := json.Marshal(claim)
	result := call(raw, 1000)
	if result.Code != 200 || strings.Contains(result.Body.String(), "private") {
		t.Fatalf("unexpected response: %d", result.Code)
	}
	if call(raw, 1001).Code != 403 {
		t.Fatal("wrong local account accepted")
	}
	claim.Captured = now.Add(time.Minute).Format(time.RFC3339)
	raw, _ = json.Marshal(claim)
	if call(raw, 1000).Code == 200 {
		t.Fatal("future capture accepted")
	}
	if calls != 1 {
		t.Fatal("invalid calls reached network")
	}
	b.config.CrashRegistrationURL = ""
	if call(raw, 1000).Code == 200 {
		t.Fatal("missing config accepted")
	}
}

func TestCrashOnlyHandlerHasNoDispatcher(t *testing.T) {
	calls := 0
	h, err := NewCrashHandler("https://plane.invalid", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "https://broker.invalid/api/crash/register", func(context.Context) (string, error) { calls++; return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/review", "/capabilities", "/dispatch", "/crash-register?extra=1"} {
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("unexpected route: %s", path)
		}
	}
	if calls != 0 {
		t.Fatal("unrelated routes accessed credentials")
	}
}
