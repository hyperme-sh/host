//go:build linux

package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/hardware"
)

func setupHaloTest(ctx context.Context, metadata, name string, out, diagnostic io.Writer) error {
	// Refuse a mismatched machine before the routine can apply prerequisites.
	profile := hardware.Detect(ctx)
	if !haloAliasMatches(name, profile.Facts.Processor) || !haloHardware(profile.Facts, profile.Facts.MemoryBytes) {
		return fmt.Errorf("requested Halo alias differs from the measured host")
	}
	var download guidedDownload
	if err := guidedRead(metadata, &download, true); err != nil {
		return err
	}
	if err := validateGuidedDownload(download); err != nil || download.Channel != "test" {
		return fmt.Errorf("use the signed TEST bootstrap metadata for this installer")
	}
	network, _ := installationNetwork("test")
	tenant, err := guidedTenant(ctx, network)
	if err != nil {
		return err
	}
	dir := haloState + "/provision"
	state := haloState + "/installer"
	unlock, err := lockSetupState(dir)
	if err != nil {
		return err
	}
	defer unlock()
	modelDir := haloState + "/models"
	if err := secureSetupDirectory(modelDir, true); err != nil {
		return err
	}
	setupPath := filepath.Join(dir, "prerequisites.json")
	readiness := network.Plane + "/api/v1/hypermesh/public/host-installation"
	if err := savedHaloPlan(ctx, setupPath, RunSetupPlan, diagnostic,
		"--memory-mode", haloMemoryMode, "--model-dir", modelDir,
		"--wireguard-mode", "kernel", "--aiuditor-check-url", readiness); err != nil {
		return err
	}
	var setup SetupPlan
	if err := guidedRead(setupPath, &setup, true); err != nil {
		return err
	}
	if !haloSetup(setup.Preflight) || setup.HeadlessRequested || setup.WireGuardMode != "kernel" ||
		setup.ReadinessURL != readiness || setup.Preflight.Resources.ModelDirectory != modelDir {
		return fmt.Errorf("saved prerequisite plan differs from the isolated Halo TEST configuration")
	}
	if RunApplySetup(ctx, []string{"--plan", setupPath, "--approve-plan", setup.PlanSHA256,
		"--state-dir", state}, io.Discard, diagnostic) != 0 {
		return fmt.Errorf("Halo prerequisite setup did not complete")
	}

	agentPath := filepath.Join(dir, "agent.json")
	if err := savedHaloPlan(ctx, agentPath, RunPlanAgent, diagnostic,
		"--setup-plan", setupPath, "--setup-state-dir", state,
		"--release-url", download.ReleaseURL, "--trusted-key", download.TrustedKey,
		"--fingerprints", download.Fingerprint, "--channel", "test", "--control-plane-url", network.Plane,
		"--tenant-id", tenant, "--host-name", name); err != nil {
		return err
	}
	var agent agentInstallPlan
	if err := guidedRead(agentPath, &agent, true); err != nil {
		return err
	}
	if agent.SetupStateDir != state || agent.TenantID != tenant || !strings.EqualFold(agent.HostName, name) {
		return fmt.Errorf("saved agent plan differs from the current Halo TEST owner scope")
	}
	return installHaloTest(ctx, agentPath, agent.SHA256, out, diagnostic)
}

func savedHaloPlan(ctx context.Context, path string, run guidedRunner, diagnostic io.Writer, args ...string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	var plan bytes.Buffer
	if run(ctx, args, &plan, diagnostic) != 0 {
		return fmt.Errorf("cannot prepare %s", filepath.Base(path))
	}
	return writeGuided(path, json.RawMessage(plan.Bytes()))
}

func haloAliasMatches(name, cpu string) bool {
	alias := strings.ToLower(name)
	return alias == "halo395-1" && halo395Processor.MatchString(cpu) ||
		alias == "halo495-1" && halo495Processor.MatchString(cpu)
}
