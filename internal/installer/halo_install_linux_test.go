//go:build linux

package installer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/agent"
	"github.com/FyberLabs/hypermesh-host/internal/hardware"
)

func TestHaloNativeScope(t *testing.T) {
	n, _ := installationNetwork("test")
	for _, tc := range []struct {
		name, cpu string
		memory    int64
	}{
		{"HALO395-1", "AMD Ryzen AI Max+ 395 w/ Radeon 8060S", 112},
		{"HALO495-1", "AMD Ryzen AI Max+ PRO 495 w/ Radeon 8060S", 172},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := hardware.Facts{Arch: "amd64", Processor: tc.cpu, Vulkan: true}
			r := Resources{SystemBytes: tc.memory * GiB, AvailableSystemBytes: 40 * GiB, DiskFreeBytes: 64 * GiB,
				UMA: true, UMARuntime: &UMARuntime{Backend: "vulkan", FreeBytes: 40 * GiB, TotalBytes: 64 * GiB}}
			fresh := Plan{Hardware: hardware.Recommend(facts), Resources: ResourceReport{MemoryMode: "uma", Resources: r, ModelDirectory: haloState + "/models"}}
			for _, os := range []struct{ id, version string }{{"ubuntu", "24.04"}, {"debian", "13"}} {
				profile, err := selectSetupProfile(fresh, SetupPlatform{OS: os.id, Version: os.version}, "auto")
				if err != nil || profile.ID != os.id+"-amd-halo-vulkan" {
					t.Fatalf("setup profile = %v, %v", profile, err)
				}
			}
			setup, _ := selectSetupProfile(fresh, SetupPlatform{OS: "debian", Version: "13"}, "auto")
			p := agentInstallPlan{ControlPlane: n.Plane, Channel: "test", HostName: tc.name,
				TenantID: "4d0316b7-ba19-40c9-931b-39a1ba4cd81a",
				Setup:    SetupPlan{Preflight: fresh, WireGuardMode: "kernel", Profile: setup}}
			j, err := newRegistration(p, n.Issuer, n.Dashboard, haloClass, fresh)
			if err != nil || !j.Request.PauseSelling {
				t.Fatalf("expected paused TEST registration: %v", err)
			}
			j.DeviceID = "1753f9d3-cc40-415b-a6b8-a54029bc3348"
			files := haloProfile(p, j)
			var state agent.State
			if err := json.Unmarshal(files[2].Data, &state); err != nil || state.ManagedScope == nil || state.DeviceID != j.DeviceID {
				t.Fatalf("dedicated enrolled identity missing: %v", err)
			}
			for _, f := range files {
				if f.Path != haloUnit && !strings.HasPrefix(f.Path, haloState+"/") && !strings.HasPrefix(f.Path, haloConfig+"/") {
					t.Fatalf("payload escaped TEST paths: %s", f.Path)
				}
			}
			env := string(files[3].Data)
			for _, value := range []string{`HYPERMESH_WG_IFACE="wg-hm-halo-test"`, `HYPERMESH_LLAMA_CTX_SIZE="32768"`, `HYPERMESH_UPDATE_CHANNEL="test"`} {
				if !strings.Contains(env, value) {
					t.Fatalf("install environment missing %s", value)
				}
			}
			for name, mutate := range map[string]func(*agentInstallPlan){
				"production plane":      func(p *agentInstallPlan) { p.ControlPlane = "https://api.hyperme.sh" },
				"production channel":    func(p *agentInstallPlan) { p.Channel = "prod" },
				"other alias":           func(p *agentInstallPlan) { p.HostName = "UNKNOWN" },
				"other model directory": func(p *agentInstallPlan) { p.Setup.Preflight.Resources.ModelDirectory = "/var/lib/hypermesh/models" },
				"headless mutation":     func(p *agentInstallPlan) { p.Setup.HeadlessRequested = true },
			} {
				bad := p
				mutate(&bad)
				if err := validateHaloScope(bad, n.Issuer, n.Dashboard, fresh); err == nil {
					t.Errorf("allowed %s", name)
				}
			}
			fresh.Resources.Resources.SystemBytes--
			if haloSetup(fresh) {
				t.Error("allowed below-minimum OS-visible RAM")
			}
		})
	}
}
