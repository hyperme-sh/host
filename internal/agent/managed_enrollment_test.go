package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/api"
)

type enrollmentRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip enrollmentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return roundTrip(req)
}

func TestManagedEnrollmentRetryUsesSameVerifier(t *testing.T) {
	cfg := Config{
		ControlPlaneURL: "https://production.example",
		TenantID:        "4592ac2e-5786-4100-a324-c06ceaff6211",
		ManagedDeviceID: "cbb164d9-6b66-4d2f-b302-b62fd354e263",
		HostName:        "example-host", EnrollToken: "test-provisioning-token",
	}
	client := api.NewClient(cfg.ControlPlaneURL, cfg.TenantID)
	var calls []api.ManagedEnrollRequest
	client.HTTP.Transport = enrollmentRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != api.PathEnroll+"/"+cfg.ManagedDeviceID {
			t.Fatalf("unexpected scoped path: %s", req.URL.Path)
		}
		var submitted api.ManagedEnrollRequest
		if err := json.NewDecoder(req.Body).Decode(&submitted); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, submitted)
		if len(calls) == 1 {
			return nil, fmt.Errorf("response lost")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	dir := t.TempDir()
	a := &Agent{cfg: cfg, client: client}
	if _, err := a.enrollManaged(context.Background(), dir, "example-public-key"); err == nil {
		t.Fatal("lost response was reported as success")
	}
	restored := &Agent{cfg: cfg, client: client}
	result, err := restored.enrollManaged(context.Background(), dir, "example-public-key")
	if err != nil || result.DeviceID != cfg.ManagedDeviceID || !strings.HasPrefix(result.DeviceSecret, "hm_dev_") {
		t.Fatalf("retry did not restore the managed credential: %v", err)
	}
	if len(calls) != 2 || calls[0] != calls[1] || len(calls[0].DeviceSecretSHA256) != 64 {
		t.Fatal("the retry changed its enrollment verifier")
	}
}

func TestManagedEnrollmentRefusesOtherStoredScopes(t *testing.T) {
	cfg := Config{ManagedDeviceID: "cbb164d9-6b66-4d2f-b302-b62fd354e263", ControlPlaneURL: "https://production.example"}
	state := State{DeviceID: cfg.ManagedDeviceID, DeviceSecret: "fixture"}
	if err := cfg.validateStateScope(state); err == nil {
		t.Fatal("accepted an unscoped state file for managed enrollment")
	}
	state.ManagedScope = cfg.scope()
	if err := cfg.validateStateScope(state); err != nil {
		t.Fatal(err)
	}
	cfg.ControlPlaneURL = "https://test.example"
	if err := cfg.validateStateScope(state); err == nil {
		t.Fatal("accepted a production credential for a different plane")
	}
}
