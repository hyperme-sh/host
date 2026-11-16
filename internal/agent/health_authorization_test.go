package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/terms"
)

func TestHealthAuthorizationCurrentEnrollmentAndRevocation(t *testing.T) {
	a := newOwnerTestAgent(t)
	st := State{DeviceID: testDevice, DeviceSecret: "synthetic-machine-secret", TermsVersion: terms.Version, TermsSHA256: terms.SHA256(), AcceptedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	if err := a.saveState(st); err != nil {
		t.Fatal(err)
	}
	status := http.StatusNoContent
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != api.PathTunnel || r.URL.Query().Get("device_id") != st.DeviceID || r.Header.Get("Authorization") != "Bearer synthetic-machine-secret" {
			t.Error("wrong authenticated machine check")
		}
		w.WriteHeader(status)
	}))
	defer server.Close()
	a.client = api.NewClient(server.URL, "synthetic-tenant")
	a.client.DeviceID, a.client.DeviceSecret = st.DeviceID, st.DeviceSecret
	check := func(want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		a.handleHealthAuthorization(w, httptest.NewRequest(http.MethodGet, "/v0/health_authorization", nil))
		if w.Code != want {
			t.Fatalf("status %d, want %d", w.Code, want)
		}
		if strings.Contains(w.Body.String(), st.DeviceSecret) {
			t.Fatal("secret in output")
		}
		return w
	}
	w := check(http.StatusOK)
	var body map[string]any
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["policy"] != "host-agreement" || body["device_id"] != st.DeviceID || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid authorization response")
	}
	status = http.StatusUnauthorized
	check(http.StatusServiceUnavailable)
	if calls != 2 {
		t.Fatal("authorization was cached")
	}
	status = http.StatusNoContent
	st.TermsSHA256 = "withdrawn"
	if err := a.saveState(st); err != nil {
		t.Fatal(err)
	}
	check(http.StatusForbidden)
	if calls != 2 {
		t.Fatal("invalid agreement reached network")
	}
}

func TestHealthAuthorizationRejectsChangedEnrollmentAndWrongCaller(t *testing.T) {
	a := newOwnerTestAgent(t)
	st := State{DeviceID: testDevice, DeviceSecret: "synthetic", TermsVersion: terms.Version, TermsSHA256: terms.SHA256(), AcceptedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	if err := a.saveState(st); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		changed := st
		changed.AcceptedAt = ""
		if err := a.saveState(changed); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	a.client = api.NewClient(server.URL, "synthetic-tenant")
	a.client.DeviceID, a.client.DeviceSecret = st.DeviceID, st.DeviceSecret
	w := httptest.NewRecorder()
	a.handleHealthAuthorization(w, httptest.NewRequest(http.MethodGet, "/v0/health_authorization", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("changed agreement accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	a.ownerHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v0/health_authorization", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated caller accepted: %d", w.Code)
	}
}
