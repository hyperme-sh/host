//go:build linux && amd64

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/runtime"
	"github.com/FyberLabs/hypermesh-host/internal/trustedmeter"
)

type trustedStarterMock struct{ starts, stops int }

func (s *trustedStarterMock) Start(_ context.Context, spec runtime.Spec) (*runtime.Handle, error) {
	s.starts++
	hash, _ := trustedmeter.Hash(*spec.TrustedMeter)
	return &runtime.Handle{LeaseID: spec.LeaseID, CatalogID: spec.CatalogID, Backend: runtime.BackendSNP, ContainerID: "unit-instance", State: runtime.HandleStarting, FileHash: "sha256:" + spec.TrustedMeter.ModelSHA256, TrustedMeterBindingSHA256: hash, TrustedMeterDial: "127.0.0.1:18443"}, nil
}
func (s *trustedStarterMock) Stop(context.Context, *runtime.Handle) error { s.stops++; return nil }
func trustedAgentFixture(t *testing.T) (*Agent, api.Job, *trustedStarterMock) {
	t.Helper()
	dir := t.TempDir()
	a := newTestAgent(t, "http://unused.invalid", dir, filepath.Join(dir, "uptime"), "", "")
	model, hash := writeTestGGUF(t, dir)
	a.cfg.GGUFPath = model
	a.bindIP = "127.0.0.1/32"
	a.cfg.TrustedMeterBundle = t.TempDir()
	a.modelFit = func(context.Context, int64) error { return nil }
	b := trustedmeter.Binding{TenantID: testTenant, DeviceID: testDevice, LeaseID: "22222222-2222-2222-2222-222222222222", GatewayID: "44444444-4444-4444-4444-444444444444", ModelSHA256: strings.TrimPrefix(hash, "sha256:"), TemplateSHA256: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64), PolicySHA256: trustedmeter.PolicySHA256, Measurement: strings.Repeat("e", 96)}
	b.TokenizerSHA256 = b.ModelSHA256
	bundle := trustedmeter.Bundle{Schema: 1, Profile: trustedmeter.GuestProfile{OwnerKey: strings.Repeat("f", 64), ModelSHA256: b.ModelSHA256, TokenizerSHA256: b.TokenizerSHA256, TemplateSHA256: b.TemplateSHA256, RuntimeSHA256: b.RuntimeSHA256, PolicySHA256: b.PolicySHA256, DriftPPM: 100}, Measurement: b.Measurement, FirmwareSHA256: strings.Repeat("a", 64), KernelSHA256: strings.Repeat("b", 64), InitrdSHA256: strings.Repeat("c", 64), CBitPos: 51, ReducedPhysBits: 1, MemoryMiB: 4096, TSCFrequencyKHz: 2400000}
	raw, _ := json.Marshal(bundle)
	if err := os.WriteFile(filepath.Join(a.cfg.TrustedMeterBundle, "bundle.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	job := ingressJob(b.LeaseID, hash)
	job.TrustedMeter = &b
	job.Runtime = runtime.BackendSNP
	job.Backend = runtime.BackendSNP
	mock := &trustedStarterMock{}
	a.trusted = mock
	return a, job, mock
}
func TestTrustedAgentStartRetryAndStop(t *testing.T) {
	a, job, mock := trustedAgentFixture(t)
	ctx := context.Background()
	if result := a.leaseStart(ctx, job); !result.Passed {
		t.Fatal(result)
	}
	if result := a.leaseStart(ctx, job); !result.Passed || mock.starts != 1 {
		t.Fatal(result, mock.starts)
	}
	ordinary := job
	ordinary.TrustedMeter = nil
	ordinary.Runtime = "nvidia"
	ordinary.Backend = "cuda-jetson"
	if a.authorizeLeaseRetry(ctx, ordinary, a.currentLease()) == nil {
		t.Fatal("ordinary retry accepted trusted handle")
	}
	a.leaseReady = func(context.Context, *runtime.Handle) error { return errors.New("guest stopped") }
	if result := a.leaseStart(ctx, job); result.Passed {
		t.Fatal("dead guest acknowledged")
	}
	if err := a.stopHandle(ctx, a.currentLease()); err != nil || mock.stops != 1 {
		t.Fatal(err, mock.stops)
	}
}
func TestTrustedAgentRefusesMissingAndChangedScope(t *testing.T) {
	for _, kind := range []string{"disabled", "missing-binding", "tenant", "device", "lease", "backend", "runtime", "private", "private-cache", "memory"} {
		t.Run(kind, func(t *testing.T) {
			a, job, mock := trustedAgentFixture(t)
			switch kind {
			case "disabled":
				a.cfg.TrustedMeterBundle = ""
			case "missing-binding":
				job.TrustedMeter = nil
			case "tenant":
				job.TrustedMeter.TenantID = "11111111-1111-1111-1111-111111111111"
			case "device":
				job.DeviceID = "11111111-1111-1111-1111-111111111111"
			case "lease":
				job.LeaseID = "11111111-1111-1111-1111-111111111111"
			case "backend":
				job.Backend = "cuda-jetson"
			case "runtime":
				job.Runtime = "nvidia"
			case "private":
				job.SourceRef = "hmblob:11111111-1111-1111-1111-111111111111"
			case "private-cache":
				if err := os.WriteFile(a.cfg.GGUFPath+".private.json", []byte("[]"), 0600); err != nil {
					t.Fatal(err)
				}
			case "memory":
				a.modelFit = func(context.Context, int64) error { return errors.New("insufficient memory") }
			}
			if result := a.leaseStart(context.Background(), job); result.Passed || mock.starts != 0 {
				t.Fatal(result, mock.starts)
			}
		})
	}
}
func TestTrustedBundleDefaultsOff(t *testing.T) {
	t.Setenv("HYPERMESH_TRUSTED_METER_BUNDLE", "")
	if FromEnv().TrustedMeterBundle != "" {
		t.Fatal("unexpected activation")
	}
}
