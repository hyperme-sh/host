package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/FyberLabs/hypermesh-host/internal/trustedmeter"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSNPDisabledAndOrdinarySpecsNeverLaunch(t *testing.T) {
	calls := 0
	s := NewSNP("", t.TempDir())
	s.Run = func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	if _, err := s.Start(context.Background(), Spec{Runtime: BackendLlamaCppCPU}); err == nil || calls != 0 {
		t.Fatal(err, calls)
	}
	s.BundleDir = t.TempDir()
	if _, err := s.Start(context.Background(), Spec{Runtime: BackendSNP, Backend: BackendSNP}); err == nil || calls != 0 {
		t.Fatal(err, calls)
	}
}
func TestSNPStopPreservesJournalAndRefusesUnsafeScope(t *testing.T) {
	state := t.TempDir()
	lease := "22222222-2222-2222-2222-222222222222"
	root := filepath.Join(state, "trusted-meter", lease)
	for _, name := range []string{"input", "boot", "journal"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSNP("", state)
	calls := 0
	s.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "/usr/bin/systemctl" || strings.Join(args, " ") != "stop hypermesh-meter-"+lease {
			t.Fatal(name, args)
		}
		return nil, nil
	}
	if err := s.Stop(context.Background(), &Handle{LeaseID: "../escape", Backend: BackendSNP}); err == nil || calls != 0 {
		t.Fatal(err, calls)
	}
	if err := s.Stop(context.Background(), &Handle{LeaseID: lease, Backend: BackendSNP}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "journal")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "input")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "boot"), 0700); err != nil {
		t.Fatal(err)
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("stop failed") }
	if s.Stop(context.Background(), &Handle{LeaseID: lease, Backend: BackendSNP}) == nil {
		t.Fatal("lost stop")
	}
	if _, err := os.Stat(filepath.Join(root, "boot")); err != nil {
		t.Fatal("cleaned running VM", err)
	}
}
func TestSNPForwardingIsLoopbackOnly(t *testing.T) {
	for _, address := range []string{"example.invalid:8443", "[::1]:8443", "127.0.0.1:1", "127.0.0.1:65536", "127.0.0.1:8443\n"} {
		if ValidTrustedDial(address) {
			t.Fatal(address)
		}
	}
	if !ValidTrustedDial("127.0.0.1:18443") {
		t.Fatal("valid dial")
	}
}

func TestSNPStartUsesOnlyFixedConfidentialLaunch(t *testing.T) {
	if !SNPEnabled() {
		t.Skip("Linux AMD64 launch contract")
	}
	dir, state := t.TempDir(), t.TempDir()
	raw := []byte("unit artifact")
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	b := trustedmeter.Binding{TenantID: "11111111-1111-1111-1111-111111111111", LeaseID: "22222222-2222-2222-2222-222222222222", DeviceID: "33333333-3333-3333-3333-333333333333", GatewayID: "44444444-4444-4444-4444-444444444444", ModelSHA256: hash, TokenizerSHA256: hash, TemplateSHA256: hash, RuntimeSHA256: hash, PolicySHA256: trustedmeter.PolicySHA256, Measurement: strings.Repeat("e", 96)}
	bundle := trustedmeter.Bundle{Schema: 1, Profile: trustedmeter.GuestProfile{OwnerKey: strings.Repeat("f", 64), ModelSHA256: hash, TokenizerSHA256: hash, TemplateSHA256: hash, RuntimeSHA256: hash, PolicySHA256: b.PolicySHA256, DriftPPM: 100}, Measurement: b.Measurement, FirmwareSHA256: hash, KernelSHA256: hash, InitrdSHA256: hash, CBitPos: 51, ReducedPhysBits: 1, MemoryMiB: 4096, TSCFrequencyKHz: 2400000}
	for _, name := range []string{"firmware.fd", "kernel", "initrd.cpio", "model.gguf"} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	encoded, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	launches := 0
	s := NewSNP(dir, state)
	s.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "/usr/bin/systemctl":
			return nil, errors.New("inactive")
		case "/usr/bin/systemd-run":
			launches++
			joined := strings.Join(args, " ")
			for _, part := range []string{"--unit=hypermesh-meter-" + b.LeaseID, "KillMode=control-group", "/usr/bin/qemu-system-x86_64", "secure-tsc=on", "kernel-hashes=on"} {
				if !strings.Contains(joined, part) {
					t.Fatal(part)
				}
			}
			return nil, nil
		default:
			t.Fatal(name)
			return nil, errors.New("unexpected command")
		}
	}
	spec := Spec{LeaseID: b.LeaseID, Runtime: BackendSNP, Backend: BackendSNP, TrustedMeter: &b, GGUFPath: filepath.Join(dir, "model.gguf")}
	h, err := s.Start(context.Background(), spec)
	if err != nil || launches != 1 || h.Serving() || h.ContainerID == "" || !ValidTrustedDial(h.TrustedMeterDial) {
		t.Fatal(h, err, launches)
	}
	s.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if _, err = s.Start(context.Background(), spec); err == nil {
		t.Fatal("duplicate active unit accepted")
	}
}
