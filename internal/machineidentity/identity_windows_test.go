//go:build windows

package machineidentity

import (
	"context"
	"encoding/json"
	"github.com/FyberLabs/hypermesh-host/internal/windowsprivate"
	"golang.org/x/sys/windows/registry"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowsSigningCheckpointRenewalAndRetirement(t *testing.T) {
	if os.Getenv("HYPERMESH_WINDOWS_UNIT_CONTRACT") != "1" {
		t.Skip("disposable Windows CI service-account contract")
	}
	if windowsprivate.RequireSystem() != nil {
		t.Fatal("contract must run as LocalSystem")
	}
	const key = `SOFTWARE\HypermeshCrashService`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.READ); err == nil {
		k.Close()
		t.Fatal("fixture requires absent machine store")
	}
	defer registry.DeleteKey(registry.LOCAL_MACHINE, key)
	now := time.Now().Truncate(time.Second)
	calls := 0
	lastKey := ""
	device := "11111111-1111-4111-8111-111111111111"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "configuration") {
			json.NewEncoder(w).Encode(map[string]string{"authority_id": "unit", "control_plane_id": "unit-plane"})
			return
		}
		var q proof
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("bad proof")
			w.WriteHeader(400)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/bind") && r.Header.Get("Authorization") != "Bearer unit-bootstrap" {
			t.Error("wrong bootstrap")
		}
		if strings.HasSuffix(r.URL.Path, "/renew") && r.Header.Get("Authorization") != "" {
			t.Error("bootstrap sent during renewal")
		}
		calls++
		lastKey = q.Public
		json.NewEncoder(w).Encode(tokenReply{Token: "hm_msi_" + device + "." + strings.Repeat("a", 43), Type: "Bearer", TTL: 300, Public: q.Public, Created: now.Unix()})
	}))
	defer server.Close()
	p := Provider{HTTP: server.Client(), Now: func() time.Time { return now }}
	if _, err := p.ExistingToken(context.Background(), server.URL, "tenant", device, "unit-bootstrap"); err == nil {
		t.Fatal("missing signer accepted bootstrap")
	}
	if _, err := p.Token(context.Background(), server.URL, "tenant", device, device, "unit-bootstrap"); err != nil {
		t.Fatal(err)
	}
	original := lastKey
	if _, err := p.ExistingToken(context.Background(), server.URL, "tenant", device, ""); err != nil || calls != 1 {
		t.Fatal("cache not reused", err)
	}
	now = now.Add(4 * time.Minute)
	if _, err := p.ExistingToken(context.Background(), server.URL, "tenant", device, ""); err != nil || calls != 2 || lastKey != original {
		t.Fatal("checkpoint renewal failed", err)
	}
	if _, err := p.ExistingToken(context.Background(), server.URL, "other", device, ""); err == nil {
		t.Fatal("tenant mismatch accepted")
	}
	now = now.Add(31 * 24 * time.Hour)
	if _, err := p.ExistingToken(context.Background(), server.URL, "tenant", device, ""); err != nil || lastKey == original {
		t.Fatal("rotation failed", err)
	}
	if err := p.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Token(context.Background(), server.URL, "tenant", device, device, "unit-bootstrap"); err == nil {
		t.Fatal("retired enrollment recreated")
	}
	if _, err := p.ExistingToken(context.Background(), server.URL, "tenant", device, "unit-bootstrap"); err == nil {
		t.Fatal("retired signer fell back")
	}
}
