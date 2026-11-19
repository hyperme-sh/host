package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/api"
)

var managedAlias = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var managedIface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$`)

type managedScope struct {
	Plane    string `json:"plane"`
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	HostName string `json:"host_name"`
}

func (c Config) validateManagedRuntime() error {
	if !managedIface.MatchString(c.WGIface) || c.WGIface == "hypermesh" || c.WGIface == "utun8" {
		return fmt.Errorf("hypermesh: managed runtime requires a dedicated WireGuard interface")
	}
	return nil
}

func (c Config) scope() *managedScope {
	if c.ManagedDeviceID == "" {
		return nil
	}
	return &managedScope{
		Plane: strings.TrimRight(c.ControlPlaneURL, "/"), TenantID: strings.ToLower(c.TenantID),
		DeviceID: strings.ToLower(c.ManagedDeviceID), HostName: c.HostName,
	}
}

// RegisteredProfileState records an already registered device in a dedicated profile.
func (c Config) RegisteredProfileState(keyDir, prefix, secret string) State {
	return State{
		ManagedScope: c.scope(), WGKeyDir: keyDir, DeviceID: c.ManagedDeviceID,
		CredentialPrefix: prefix, DeviceSecret: secret,
	}
}

func (c Config) validateStateScope(st State) error {
	expected := c.scope()
	if expected == nil && st.ManagedScope == nil {
		return nil
	}
	if expected != nil && st.DeviceID == "" && st.ManagedScope == nil {
		return nil
	}
	if expected == nil || st.ManagedScope == nil || *expected != *st.ManagedScope ||
		!strings.EqualFold(st.DeviceID, expected.DeviceID) || st.DeviceSecret == "" {
		return fmt.Errorf("hypermesh: stored device belongs to a different enrollment scope")
	}
	return nil
}

// The pending file exists before Plane commits. A lost response can be replayed
// with the original verifier and WireGuard key.
func (a *Agent) managedCredential(keyDir string) (string, error) {
	path := filepath.Join(keyDir, "managed-device-secret.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		tmp, err := os.MkdirTemp(keyDir, "managed-secret-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(tmp)
		staged := filepath.Join(tmp, "credential.json")
		if err := writeJSON0600(staged, "hm_dev_"+base64.RawURLEncoding.EncodeToString(raw)); err != nil {
			return "", err
		}
		if err := os.Link(staged, path); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 80 {
		return "", fmt.Errorf("hypermesh: unsafe managed enrollment credential file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var secret string
	if err := json.Unmarshal(data, &secret); err != nil || !strings.HasPrefix(secret, "hm_dev_") {
		return "", fmt.Errorf("hypermesh: invalid managed enrollment credential file")
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(secret[len("hm_dev_"):]); err != nil || len(decoded) != 24 {
		return "", fmt.Errorf("hypermesh: invalid managed enrollment credential file")
	}
	dir, err := os.Open(keyDir)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return "", err
	}
	return secret, nil
}

func (a *Agent) enrollManaged(ctx context.Context, keyDir, publicKey string) (api.EnrollResponse, error) {
	// This path runs only for fresh enrollment or its retry. Existing
	// identities return before reaching it, preserving their owner posture.
	if err := writeJSON0600(a.sellPath(), SellPosture{SellState: api.SellPaused, Source: SellSourceOwner}); err != nil {
		return api.EnrollResponse{}, err
	}
	secret, err := a.managedCredential(keyDir)
	if err != nil {
		return api.EnrollResponse{}, err
	}
	scope := a.cfg.scope()
	prefix := secret[len("hm_dev_") : len("hm_dev_")+8]
	err = a.client.EnrollManaged(ctx, scope.DeviceID, api.ManagedEnrollRequest{
		HostName: scope.HostName, WGPublicKey: publicKey, EnrollToken: a.cfg.EnrollToken,
		DeviceSecretSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(secret))), CredentialPrefix: prefix,
	})
	if err != nil {
		return api.EnrollResponse{}, err
	}
	return api.EnrollResponse{DeviceID: scope.DeviceID, DeviceSecret: secret, CredentialPrefix: prefix}, nil
}
