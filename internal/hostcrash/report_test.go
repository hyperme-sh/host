package hostcrash

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const tenant = "11111111-1111-4111-8111-111111111111"
const device = "22222222-2222-4222-8222-222222222222"

func TestEventFixedSchema(t *testing.T) {
	event, err := NewEvent(tenant, time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if json.Unmarshal(event.Body, &body) != nil {
		t.Fatal("json")
	}
	if len(body) != 8 || body["message"] != "Host Go runtime terminated unexpectedly" || body["platform"] != "go" {
		t.Fatal(body)
	}
	if _, err := NewEvent("secret/prompt", time.Now()); err == nil {
		t.Fatal("invalid tenant")
	}
}
func TestDestinationRefusesUnsafeConfig(t *testing.T) {
	for _, dsn := range []string{"http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@host/1", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:secret@host/1", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@host/01", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@host/1?secret=1", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@host/%31", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@other/1", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@host/prefix/1"} {
		if _, err := ParseDestination(dsn, "https://host/api/crash/register"); err == nil {
			t.Fatal(dsn)
		}
	}
}
func TestRegisteredExactEnvelopeAndRefusals(t *testing.T) {
	event, _ := NewEvent(tenant, time.Now())
	uploads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads++
		raw, _ := io.ReadAll(r.Body)
		parts := bytes.SplitN(raw, []byte("\n"), 3)
		if r.URL.Path != "/api/7/envelope/" || len(parts) != 3 || !bytes.Equal(parts[2], event.Body) {
			t.Error("changed event")
		}
		if r.Header.Get("Authorization") != "" || !strings.Contains(r.Header.Get("X-Sentry-Auth"), "sentry_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
			t.Error("auth boundary")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	old := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = old }()
	d, err := ParseDestination(strings.Replace(server.URL, "https://", "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@", 1)+"/7", server.URL+"/api/crash/register")
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"version": 1, "registered": true, "tenant": tenant, "subject": "subject", "device": device, "project": 7, "event_id": event.ID, "captured_at": event.Captured, "payload_sha256": event.Hash}
	register := func(context.Context, Event) ([]byte, error) { return json.Marshal(base) }
	if err = d.Send(context.Background(), tenant, device, event, register); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tenant", "device", "project", "event_id", "captured_at", "payload_sha256", "subject", "version", "registered"} {
		original := base[key]
		base[key] = nil
		if d.Send(context.Background(), tenant, device, event, register) == nil {
			t.Fatal("accepted changed " + key)
		}
		base[key] = original
	}
	if uploads != 1 {
		t.Fatal("unexpected uploads", uploads)
	}
}
