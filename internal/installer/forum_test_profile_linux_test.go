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
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
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
			ReadinessURL:  network.Plane + "/api/v1/hypermesh/public/host-installation",
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

func TestJ4012ForumCertificationPinsTheSeparateQwenArtifact(t *testing.T) {
	plan := certificationPlan{
		Agent: agentInstallPlan{TenantID: forumCertificationTenant},
		Run: hostregistration.CertificationRun{Manifest: hostregistration.CertificationManifest{
			ClassID: "nx-volume", CatalogID: "qwen-2.5-7b-q4", FileHash: "sha256:" + forumCertificationDigest,
			SizeBytes: 4683074240, FullContext: true,
		}},
	}
	if err := validateForumCertificationModel(plan); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*certificationPlan){
		"canonical tenant": func(p *certificationPlan) { p.Agent.TenantID = "8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d" },
		"other model":      func(p *certificationPlan) { p.Run.Manifest.CatalogID = "llama-3-1-8b" },
		"other bytes":      func(p *certificationPlan) { p.Run.Manifest.FileHash = "sha256:" + strings.Repeat("a", 64) },
		"partial context":  func(p *certificationPlan) { p.Run.Manifest.FullContext = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := plan
			change(&bad)
			if err := validateForumCertificationModel(bad); err == nil {
				t.Fatal("accepted a workload outside the forum TEST pins")
			}
		})
	}
	if certificationSetupState(true) != forumState+"/installer" || certificationSetupState(false) == certificationSetupState(true) {
		t.Fatal("certification must keep its journal in the dedicated TEST profile")
	}
	if certificationLockState(true) != forumTestProfile.state || certificationLockState(false) != defaultSetupState {
		t.Fatal("certification must take the same lock as its installer")
	}
	var output, diagnostic bytes.Buffer
	if code := RunActivateAgent(context.Background(), []string{"--forum-test"}, &output, &diagnostic); code != 2 {
		t.Fatalf("activation accepted the forum TEST selector: %s", diagnostic.String())
	}
}

func TestForumQualificationRequiresTheInstalledModelAndPlan(t *testing.T) {
	for _, args := range [][]string{
		{"--forum-test"},
		{"--forum-test", "--agent-plan", "fixture.json", "--model-token-file", "fixture-token"},
	} {
		var diagnostic bytes.Buffer
		result := RunQualifyHost(context.Background(), args, strings.NewReader(""), &bytes.Buffer{}, &diagnostic)
		if result != 2 || !strings.Contains(diagnostic.String(), "uses the installed Qwen model") {
			t.Fatalf("expected scoped argument refusal, got %d (%s)", result, diagnostic.String())
		}
	}
	p := certificationPlan{Agent: agentInstallPlan{TenantID: forumCertificationTenant}}
	j := qualificationJournal{Run: hostregistration.QualificationRun{
		CertificationRun: hostregistration.CertificationRun{Manifest: hostregistration.CertificationManifest{
			CatalogID: "llama", ClassID: "nx-volume", FullContext: true,
		}},
	}}
	err := collectQualification(context.Background(), p, registrationJournal{}, nil, &j, "", "", &bytes.Buffer{}, true, nil)
	if err == nil || !strings.Contains(err.Error(), "pinned s3r.ch TEST Qwen") {
		t.Fatalf("qualification accepted an unrelated model: %v", err)
	}
}
