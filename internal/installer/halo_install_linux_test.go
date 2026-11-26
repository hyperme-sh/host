//go:build linux

package installer

import (
	"bytes"
	"context"
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
			fresh := Plan{Hardware: hardware.Recommend(facts), Resources: ResourceReport{MemoryMode: haloMemoryMode, Resources: r, ModelDirectory: haloState + "/models"}}
			for _, os := range []struct{ id, version string }{{"ubuntu", "24.04"}, {"ubuntu", "26.10"}, {"debian", "13"}} {
				profile, err := selectSetupProfile(fresh, SetupPlatform{OS: os.id, Version: os.version}, "auto")
				if err != nil || profile.ID != os.id+"-amd-halo-vulkan" {
					t.Fatalf("setup profile = %v, %v", profile, err)
				}
			}
			setup, _ := selectSetupProfile(fresh, SetupPlatform{OS: "debian", Version: "13"}, "auto")
			p := agentInstallPlan{ControlPlane: n.Plane, Channel: "test", HostName: tc.name,
				TenantID: "4d0316b7-ba19-40c9-931b-39a1ba4cd81a",
				Setup:    SetupPlan{Preflight: fresh, WireGuardMode: "kernel", Profile: setup, ReadinessURL: n.Plane + "/api/v1/hypermesh/public/host-installation"}}
			j, err := newRegistration(p, n.Issuer, n.Dashboard, haloClass, fresh)
			if err != nil || !j.Request.PauseSelling {
				t.Fatalf("expected paused TEST registration: %v", err)
			}
			j.DeviceID = "1753f9d3-cc40-415b-a6b8-a54029bc3348"
			files := haloProfile(p, j)
			var posture struct {
				SellState string `json:"sell_state"`
				Source    string `json:"source"`
			}
			if err := json.Unmarshal(files[1].Data, &posture); err != nil || posture.SellState != "n/a" || posture.Source != "" {
				t.Fatalf("isolated install must enroll unadvertised without recording an owner pause: %+v, %v", posture, err)
			}

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
			if _, err := selectSetupProfile(fresh, SetupPlatform{OS: "ubuntu", Version: "26.10"}, "auto"); err == nil {
				t.Error("allowed Ubuntu 26.10 outside the Halo Vulkan profile")
			}
		})
	}
}

func TestHaloVulkanPlanWithROCmInstalled(t *testing.T) {
	var out, diagnostics bytes.Buffer
	detect := func(context.Context) hardware.Profile {
		return hardware.Recommend(hardware.Facts{
			Arch: "amd64", Processor: "AMD Ryzen AI Max+ 395", HIP: true, GPU: "ROCm GPU",
		})
	}
	probe := func(_ context.Context, _, mode string, allocation int64) (Resources, error) {
		if mode != haloMemoryMode || allocation != 0 {
			t.Fatalf("unexpected Halo probe mode or allocation: %s %d", mode, allocation)
		}
		return Resources{UMA: true, SystemBytes: 112 * GiB, AvailableSystemBytes: 40 * GiB, DiskFreeBytes: 64 * GiB,
			UMARuntime: &UMARuntime{Backend: "vulkan", FreeBytes: 40 * GiB, TotalBytes: 64 * GiB}}, nil
	}
	code := runPlan(context.Background(), []string{"--memory-mode", haloMemoryMode, "--model-dir", ".",
		"--aiuditor-check-url", "https://example.invalid/ready"}, &out, &diagnostics, probe, detect,
		func(context.Context, string) error { return nil })
	var plan Plan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil || code != 0 || !haloSetup(plan) {
		t.Fatalf("Halo Vulkan plan failed: code=%d err=%v blockers=%v %s", code, err, plan.Blockers, diagnostics.String())
	}
}

func TestHaloSetupPlansDockerAndWireGuard(t *testing.T) {
	p, source := setupFixture()
	p.Hardware = hardware.Recommend(hardware.Facts{
		Arch: "amd64", Processor: "AMD Ryzen AI Max+ PRO 495", Vulkan: true,
	})
	r := &p.Resources.Resources
	r.SystemBytes, r.UMAAllocationBytes = 192*GiB, 0
	r.UMARuntime.Backend = "vulkan"
	p.Resources.MemoryMode = haloMemoryMode
	p.Resources.Admission = CheckResources(*r)
	existing := "mesa-vulkan-drivers:amd64\t26.0\tii \n" +
		"iproute2\t1\tii \niputils-ping\t1\tii \nca-certificates\t1\tii \ngnupg\t1\tii \npython3\t1\tii \n"
	serviceState := "not-found"
	var simulations int
	source.Output = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			if args[0] == "show" {
				return []byte(serviceState), nil
			}
			return []byte("graphical.target"), nil
		case "dpkg-query":
			return []byte(existing), nil
		case "apt-cache":
			return []byte("Candidate: 1\n"), nil
		case "apt-get":
			simulations++
			return []byte("Inst containerd (1 Ubuntu [amd64])\nInst docker.io (1 Ubuntu [amd64])\n" +
				"Inst wireguard-tools (1 Ubuntu [amd64])\nConf containerd (1 Ubuntu [amd64])\n" +
				"Conf docker.io (1 Ubuntu [amd64])\nConf wireguard-tools (1 Ubuntu [amd64])\n"), nil
		default:
			t.Fatalf("unexpected setup command %s", name)
			return nil, nil
		}
	}
	plan := buildSetupPlan(context.Background(), p, "auto", "kernel", false, source)
	if !plan.Reviewable || len(plan.Packages) != 3 || len(plan.Changes) != 1 || simulations != 2 {
		t.Fatalf("missing pinned Halo prerequisite transaction: %+v", plan)
	}
	for _, value := range []string{"docker.io=1", "containerd=1", "wireguard-tools=1"} {
		if !strings.Contains(strings.Join(plan.Changes[0].Argv, " "), value) {
			t.Fatalf("setup did not pin %s", value)
		}
	}
	serviceState = "loaded"
	if buildSetupPlan(context.Background(), p, "auto", "kernel", false, source).Reviewable {
		t.Fatal("setup accepted an unmanaged Docker service")
	}
}
