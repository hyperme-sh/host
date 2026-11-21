//go:build linux || darwin

package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/agent"
)

func automaticNativeInputs() (registration, model, binary string, err error) {
	registration = os.Getenv("HYPERMESH_NATIVE_REGISTRATION_PLAN_SHA")
	model = os.Getenv("HYPERMESH_NATIVE_MODEL_FILE")
	binary = os.Getenv("HYPERMESH_NATIVE_RUNTIME_FILE")
	if !macSHA.MatchString(registration) || !filepath.IsAbs(model) || !filepath.IsAbs(binary) {
		err = fmt.Errorf("native certification inputs are not provisioned")
	}
	return
}

type nativeProvisionedInputs struct {
	Registration string `json:"registration_plan_sha256"`
	Model        string `json:"model_file"`
	Runtime      string `json:"runtime_file"`
}

func readNativeProvisionedInputs(dir string) (nativeProvisionedInputs, error) {
	var provisioned nativeProvisionedInputs
	path := filepath.Join(dir, "native-certification.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		provisioned.Registration, provisioned.Model, provisioned.Runtime, err = automaticNativeInputs()
		return provisioned, err
	} else if err != nil {
		return provisioned, err
	}
	raw, err := macRead(path, 0600, 16<<10)
	if err != nil {
		return provisioned, err
	}
	if err := macDecode(raw, &provisioned); err != nil {
		return provisioned, err
	}
	if !macSHA.MatchString(provisioned.Registration) ||
		!filepath.IsAbs(provisioned.Model) || !filepath.IsAbs(provisioned.Runtime) {
		return provisioned, fmt.Errorf("invalid provisioned native certification inputs")
	}
	return provisioned, nil
}

// RunAutomaticNative reads deployment-provisioned pinned inputs. It uses the
// same private journal and evidence checks as the manual native collector.
func RunAutomaticNative(ctx context.Context, cfg agent.Config, state agent.State, shape string) error {
	if !strings.HasPrefix(shape, "sha256:") || !macSHA.MatchString(strings.TrimPrefix(shape, "sha256:")) {
		return fmt.Errorf("invalid automatic native shape")
	}
	inputs, err := readNativeProvisionedInputs(macPath("", cfg.StateDir))
	if err != nil {
		return err
	}
	registration, model, binary := inputs.Registration, inputs.Model, inputs.Runtime
	dir := macPath("", filepath.Join(cfg.StateDir, "native-automatic"))
	if err := macDirectory(dir, true, true); err != nil {
		return err
	}
	prefix := filepath.Join(dir, "run-"+strings.TrimPrefix(shape, "sha256:")+"-")
	matches, err := filepath.Glob(prefix + "*.json")
	if err != nil {
		return err
	}
	path := prefix + time.Now().UTC().Format("20060102T150405.000000000") + ".json"
	for i := len(matches) - 1; i >= 0; i-- {
		if strings.HasSuffix(matches[i], ".evidence.json") || strings.HasSuffix(matches[i], ".result.json") {
			continue
		}
		raw, err := nativeRead(matches[i])
		if err != nil {
			return err
		}
		var existing nativePlan
		if err := macDecode(raw, &existing); err != nil {
			return err
		}
		if existing.RegistrationSHA == registration && (existing.Run == nil || existing.Run.ExpiresAt.After(time.Now())) {
			path = matches[i]
		}
		break
	}
	ctx = context.WithValue(ctx, automaticNativeKey{}, automaticNative{device: state.DeviceID, tenant: cfg.TenantID, shape: shape})
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	protocol := []string{}
	if nativeAutomaticHalo {
		protocol = []string{"--halo-test"}
	}
	planArgs := append(append([]string{}, protocol...), "--registration-plan-sha", registration, "--plan", path)
	if RunPlanCertification(ctx, planArgs, io.Discard, io.Discard) != 0 {
		return fmt.Errorf("automatic native planning failed")
	}
	raw, err := nativeRead(path)
	if err != nil {
		return err
	}
	var plan nativePlan
	if err := macDecode(raw, &plan); err != nil {
		return err
	}
	if plan.Run == nil || plan.Run.Manifest.ShapeSignature != shape {
		return fmt.Errorf("automatic native assignment differs from approved hardware")
	}
	args := append(append([]string{}, protocol...), "--plan", path, "--approve-plan", nativePlanDigest(plan),
		"--run", "--model-file", model, "--runtime-file", binary, "--artifact-dir", dir)
	runContext, stop := context.WithDeadline(ctx, plan.Run.ExpiresAt.Add(-time.Minute))
	defer stop()
	if RunCertifyAgent(runContext, args, io.Discard, io.Discard) != 0 {
		return fmt.Errorf("automatic native measurements or result submission failed")
	}
	return nil
}
