//go:build linux

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRelativeStateDirStillReturnsBearerCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	if err := os.Mkdir("state", 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ControlPlaneURL: "https://cp.example", TenantID: "t1", StateDir: "./state"}
	if path := machineIdentityPath(cfg); !filepath.IsAbs(path) {
		t.Fatalf("path %q is not absolute", path)
	}
	c := machineAPIClient(cfg)
	c.DeviceID = "device-1"
	c.DeviceSecret = "bootstrap-secret"
	token, err := c.Credential(context.Background())
	if err != nil || token != "bootstrap-secret" {
		t.Fatalf("credential = %q, %v", token, err)
	}
}

func TestManagedHostKeepsExistingRegistrationSigningContext(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const device = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const request = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	now := time.Now()
	state, err := json.Marshal(map[string]any{
		"schema": 1, "base": "https://cp.example", "tenant": "t1",
		"authority_id": "authority", "control_plane_id": "plane",
		"device": device, "request": request, "key": base64.StdEncoding.EncodeToString(key),
		"bound": true, "created": now.Unix(), "token": "cached-test-token",
		"expires": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "machine-identity.json")
	if err := os.WriteFile(path, state, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{ControlPlaneURL: "https://cp.example", TenantID: "t1", StateDir: dir, ManagedDeviceID: device}
	client := machineAPIClient(cfg)
	client.DeviceID, client.DeviceSecret = device, "bootstrap-secret"
	token, err := client.Credential(context.Background())
	if err != nil || token != "cached-test-token" {
		t.Fatalf("managed context not reused: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(state) {
		t.Fatal("managed checkpoint changed")
	}
}
