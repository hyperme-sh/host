//go:build linux

package installer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/FyberLabs/hypermesh-host/internal/agent"
	"github.com/FyberLabs/hypermesh-host/internal/hardware"
)

func TestJ4012ForumProfileUsesAnIndependentPausedEnrollment(t *testing.T) {
	network, _ := installationNetwork("test")
	fresh := Plan{
		Hardware: hardware.Profile{Backend: "cuda", Facts: hardware.Facts{Arch: "arm64", Tegra: true, Model: "NVIDIA Jetson Orin NX"}},
		Resources: ResourceReport{
			Resources:      Resources{SystemBytes: 16 * GiB},
			Admission:      Admission{AcceleratorBytes: 12 * GiB},
			ModelDirectory: forumState + "/models",
		},
	}
	plan := agentInstallPlan{ControlPlane: network.Plane, Channel: "test", HostName: "J4012-1",
		TenantID: "afee9b29-1706-5590-bbbf-e58df8945ac0", SetupStateDir: forumState + "/installer",
		Setup: SetupPlan{Profile: &SetupProfile{ID: "ubuntu-jetson"}, Preflight: fresh,
			ReadinessURL: network.Plane + "/api/v1/hypermesh/public/host-installation",
			WireGuardMode: "kernel"}}
	if err := validateForumTestScope(plan, network.Issuer, network.Dashboard, fresh); err != nil {
		t.Fatal(err)
	}
	j, err := newRegistrationWithPause(plan, network.Issuer, network.Dashboard, "nx-volume", fresh, true)
	if err != nil || !j.Request.PauseSelling {
		t.Fatalf("paused registration unavailable: %v", err)
	}
	j.DeviceID, j.State = "1753f9d3-cc40-415b-a6b8-a54029bc3348", "registered-inactive"
	j.Owner = "3a03f17b-26b6-438d-9f06-6ca6c889baa0"
	if err := validateRegistrationWithPause(j, plan, network.Issuer, network.Dashboard, "nx-volume", true); err != nil {
		t.Fatal(err)
	}
	files := isolatedTestAgent(plan, j, forumTestProfile)
	var state agent.State
	if err := json.Unmarshal(files[2].Data, &state); err != nil || state.ManagedScope == nil || state.DeviceID != j.DeviceID {
		t.Fatalf("independent enrolled identity unavailable: %v", err)
	}
	for _, file := range files {
		if file.Path != forumTestProfile.unit && !strings.HasPrefix(file.Path, forumState+"/") &&
			!strings.HasPrefix(file.Path, forumTestProfile.config+"/") {
			t.Errorf("file escaped forum TEST paths: %s", file.Path)
		}
	}
	for _, entry := range []string{`HYPERMESH_WG_IFACE="wg-hm-forum"`, `HYPERMESH_LISTEN_PORT="8094"`,
		`HYPERMESH_UPDATE_CHANNEL="test"`, `HYPERMESH_LLAMA_CTX_SIZE="4096"`} {
		if !strings.Contains(string(files[3].Data), entry+"\n") {
			t.Errorf("missing independent runtime setting %s", entry)
		}
	}
	for name, mutate := range map[string]func(*agentInstallPlan){
		"production channel": func(p *agentInstallPlan) { p.Channel = "prod" },
		"production Plane":   func(p *agentInstallPlan) { p.ControlPlane = "https://api.hyperme.sh" },
		"other device":       func(p *agentInstallPlan) { p.HostName = "agx64-1" },
		"old model directory": func(p *agentInstallPlan) {
			p.Setup.Preflight.Resources.ModelDirectory = "/var/lib/hypermesh/models"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := plan
			mutate(&bad)
			if err := validateForumTestScope(bad, network.Issuer, network.Dashboard, fresh); err == nil {
				t.Fatal("plan outside the dedicated TEST profile was accepted")
			}
		})
	}
}
