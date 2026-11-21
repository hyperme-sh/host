//go:build linux || darwin

package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

type nativePlan struct {
	AutomaticShape  string                      `json:"automatic_shape,omitempty"`
	Schema          int                         `json:"schema"`
	RegistrationSHA string                      `json:"registration_sha256"`
	RunID           string                      `json:"run_id"`
	Environment     string                      `json:"environment_hash"`
	Hardware        string                      `json:"hardware_fingerprint"`
	FirstReference  bool                        `json:"first_reference,omitempty"`
	Run             *hostregistration.NativeRun `json:"run,omitempty"`
}
type nativeRemote interface {
	PlanNativeCertification(context.Context, hostregistration.Request, string, string, string, string, string) (hostregistration.NativeRun, error)
	ReportNativeCertification(context.Context, hostregistration.Request, string, string, hostregistration.NativeRun, hostregistration.NativeEvidence) (hostregistration.NativeRun, error)
}
type nativeInstallation struct {
	journal       registrationJournal
	plane, tenant string
	check         func(context.Context) error
}

type nativeDeps struct {
	installation func(context.Context, string, string) (nativeInstallation, error)
	stateDir     string
	lock         func(string) (func(), error)
	backend      string
	registration macRegistrationDeps
	inventory    func(context.Context) (string, string, error)
	remote       func(string, string) (nativeRemote, error)
	measure      func(context.Context, []string, io.Writer, io.Writer) int
}

type automaticNativeKey struct{}

type automaticNative struct {
	device, tenant, shape string
}

func nativeAutomatic(ctx context.Context) (automaticNative, bool) {
	settings, ok := ctx.Value(automaticNativeKey{}).(automaticNative)
	return settings, ok
}

func nativePlanDigest(p nativePlan) string { raw, _ := json.Marshal(p); return macDigest(raw) }

func runNativeCertification(ctx context.Context, args []string, out, diagnostic io.Writer, planning bool, d nativeDeps) int {
	automatic, managed := nativeAutomatic(ctx)
	flags := flag.NewFlagSet("native-certification", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	path := flags.String("plan", "", "private native certification plan file (created by plan-certification)")
	registration := flags.String("registration-plan-sha", "", "saved installation plan digest; planning only")
	firstReference := flags.Bool("first-reference", false, "plan native measurements for operator review before a class reference exists")
	var agentPlan string
	if d.installation != nil {
		flags.StringVar(&agentPlan, "agent-plan", "", "original approved agent plan for a separately installed Halo TEST profile")
	}
	approved := flags.String("approve-plan", "", "reviewed native plan digest")
	run := flags.Bool("run", false, "run the approved native workload and submit its measurements")
	model := flags.String("model-file", "", "local pinned GGUF")
	binary := flags.String("runtime-file", "", "local pinned llama-bench")
	artifacts := flags.String("artifact-dir", "", "private directory for complete local reports")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(diagnostic, err); return 1 }
	if (!planning && *firstReference) || flags.NArg() != 0 || !filepath.IsAbs(*path) || (planning && !macSHA.MatchString(*registration)) || (!planning && (!*run || !macSHA.MatchString(*approved))) {
		return fail(fmt.Errorf("require an absolute --plan; planning requires --registration-plan-sha; execution requires --approve-plan and --run"))
	}
	// Resolve only Darwin's fixed root-owned /var and /etc aliases.
	*path = macPath("", *path)
	if *artifacts != "" {
		*artifacts = macPath("", *artifacts)
	}
	state := d.stateDir
	lock := d.lock
	if d.installation == nil {
		state = macPath(d.registration.root, macRegistrationState)
		lock = macLock
	}
	unlock, err := lock(state)
	if err != nil {
		return fail(err)
	}
	defer unlock()
	var p nativePlan
	raw, err := nativeRead(*path)
	newPlan := os.IsNotExist(err)
	if newPlan {
		if !planning {
			return fail(err)
		}
		id, e := hostregistration.NewRunID()
		if e != nil {
			return fail(e)
		}
		environment, hardware, e := d.inventory(ctx)
		if e != nil {
			return fail(e)
		}
		p = nativePlan{Schema: 1, RegistrationSHA: *registration, RunID: id, Environment: environment, Hardware: hardware, FirstReference: *firstReference, AutomaticShape: automatic.shape}
	} else if err != nil {
		return fail(err)
	} else if err = macDecode(raw, &p); err != nil {
		return fail(err)
	}
	if p.Schema != 1 || !macSHA.MatchString(p.RegistrationSHA) || !hostregistration.UUID.MatchString(p.RunID) || !strings.HasPrefix(p.Environment, "sha256:") || !macSHA.MatchString(strings.TrimPrefix(p.Environment, "sha256:")) || !macSHA.MatchString(p.Hardware) || (planning && (p.RegistrationSHA != *registration || p.FirstReference != *firstReference)) {
		return fail(fmt.Errorf("invalid native plan"))
	}
	if p.AutomaticShape != automatic.shape {
		return fail(fmt.Errorf("native automatic plan is bound to another hardware shape"))
	}
	if !planning && (p.Run == nil || nativePlanDigest(p) != *approved) {
		return fail(fmt.Errorf("native plan digest differs"))
	}
	load := d.installation
	if load == nil {
		load = func(ctx context.Context, digest, _ string) (nativeInstallation, error) {
			return macNativeInstallation(ctx, d, state, digest)
		}
	}
	installation, err := load(ctx, p.RegistrationSHA, agentPlan)
	if err != nil {
		return fail(err)
	}
	j := installation.journal
	if managed && (j.DeviceID != automatic.device || installation.tenant != automatic.tenant) {
		return fail(fmt.Errorf("native plan belongs to another enrolled agent"))
	}
	check := func() error {
		if err := installation.check(ctx); err != nil {
			return err
		}
		environment, hardware, err := d.inventory(ctx)
		if err != nil {
			return err
		}
		if environment != p.Environment || hardware != p.Hardware {
			return fmt.Errorf("native inventory changed; plan a new run")
		}
		return nil
	}
	if err = check(); err != nil {
		return fail(err)
	}
	client, err := d.remote(installation.plane, installation.tenant)
	if err != nil {
		return fail(err)
	}
	save := func() error {
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		return macWrite(*path, raw, !newPlan)
	}
	if planning {
		if newPlan {
			if err = save(); err != nil {
				return fail(err)
			}
			newPlan = false
		}
		if p.Run == nil {
			plan := client.PlanNativeCertification
			if managed {
				scheduler, ok := client.(interface {
					PlanAutomaticNativeCertification(context.Context, hostregistration.Request, string, string, string, string, string) (hostregistration.NativeRun, error)
				})
				if !ok {
					return fail(fmt.Errorf("automatic native planning unavailable"))
				}
				plan = scheduler.PlanAutomaticNativeCertification
			}
			if p.FirstReference {
				referenceClient, ok := client.(interface {
					PlanNativeReference(context.Context, hostregistration.Request, string, string, string, string, string) (hostregistration.NativeRun, error)
				})
				if !ok {
					return fail(fmt.Errorf("native reference planning unavailable"))
				}
				plan = referenceClient.PlanNativeReference
			}
			result, e := plan(ctx, j.Request, j.DeviceID, j.DeviceSecret, p.RunID, p.Environment, p.Hardware)
			if e != nil {
				return fail(e)
			}
			if managed && result.Manifest.ShapeSignature != automatic.shape {
				return fail(fmt.Errorf("native assignment does not match the approved hardware shape"))
			}
			if result.Manifest.CollectorCommit != buildinfo.Current() {
				return fail(fmt.Errorf("reviewed collector revision differs from this CLI; request identity retained for retry"))
			}
			p.Run = &result
			if err = save(); err != nil {
				return fail(err)
			}
		}
		return printNativePlan(out, *path, p)
	}
	m := p.Run.Manifest
	if (m.Purpose == hostregistration.NativeReferencePurpose) != p.FirstReference || m.Validate() != nil || m.CollectorCommit != buildinfo.Current() || m.EnvironmentHash != p.Environment || m.Hardware != p.Hardware || p.Run.DeviceID != j.DeviceID || p.Run.RequestID != j.Request.RequestID || p.Run.TenantID != installation.tenant {
		return fail(fmt.Errorf("native workload or installation binding differs"))
	}
	evidencePath := *path + ".evidence.json"
	var evidence hostregistration.NativeEvidence
	raw, err = nativeRead(evidencePath)
	if os.IsNotExist(err) {
		if !p.Run.ExpiresAt.After(time.Now()) {
			return fail(fmt.Errorf("native plan expired; prepare a fresh run before measuring"))
		}
		if *model == "" || *binary == "" || !filepath.IsAbs(*artifacts) {
			return fail(fmt.Errorf("require local model/runtime and an absolute private artifact directory"))
		}
		if err = macDirectory(*artifacts, true, true); err != nil {
			return fail(err)
		}
		info, e := os.Stat(*model)
		if e != nil || info.Size() != m.SizeBytes {
			return fail(fmt.Errorf("model size differs from the native plan"))
		}
		// The collector hashes an open descriptor but exec resolves a path.
		// Protect that resolution against lower-privileged rename/replacement.
		*binary = macPath("", *binary)
		if e = trustedNativeRuntime(*binary, d.registration.root); e != nil {
			return fail(e)
		}
		backend, stateDir := d.backend, d.stateDir
		if backend == "" {
			backend, stateDir = "metal", macPath(d.registration.root, "/var/lib/hypermesh")
		}
		var output bytes.Buffer
		code := d.measure(ctx, []string{"--model-file", *model, "--model-sha256", strings.TrimPrefix(m.FileHash, "sha256:"), "--runtime-file", *binary, "--runtime-sha256", m.RuntimeSHA256, "--backend", backend, "--device", m.Device, "--samples", "3", "--context-tokens", fmt.Sprint(m.ContextTokens), "--generated-tokens", "32", "--artifact-dir", *artifacts, "--state-dir", stateDir}, &output, diagnostic)
		if code != 0 {
			return fail(fmt.Errorf("native measurement failed; complete report retained in the artifact directory"))
		}
		reportPath := strings.TrimSpace(output.String())
		rel, e := filepath.Rel(*artifacts, reportPath)
		if e != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return fail(fmt.Errorf("unexpected native report path"))
		}
		raw, e = macRead(reportPath, 0600, 2<<20)
		if e != nil {
			return fail(e)
		}
		var report certmeasure.Report
		if e = macDecode(raw, &report); e != nil {
			return fail(e)
		}
		evidence, e = nativeEvidence(report, m)
		if e != nil {
			return fail(e)
		}
		if e = check(); e != nil {
			return fail(e)
		}
		raw, e = json.Marshal(evidence)
		if e != nil {
			return fail(e)
		}
		if e = macWrite(evidencePath, raw, false); e != nil {
			return fail(e)
		}
	} else if err != nil {
		return fail(err)
	} else if err = macDecode(raw, &evidence); err != nil {
		return fail(err)
	}
	if err = check(); err != nil {
		return fail(err)
	}
	result, err := client.ReportNativeCertification(ctx, j.Request, j.DeviceID, j.DeviceSecret, *p.Run, evidence)
	if err != nil {
		return fail(err)
	}
	// Keep the approved plan unchanged. The immutable receipt is a separate file.
	resultRaw, _ := json.Marshal(result)
	if old, e := nativeRead(*path + ".result.json"); e == nil {
		var prior hostregistration.NativeRun
		if macDecode(old, &prior) != nil || prior.RunID != result.RunID || prior.State != result.State || prior.ManifestSHA256 != result.ManifestSHA256 {
			return fail(fmt.Errorf("native result conflicts with retained receipt"))
		}
	} else if !os.IsNotExist(e) {
		return fail(e)
	} else if e = macWrite(*path+".result.json", resultRaw, false); e != nil {
		return fail(e)
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"run_id": result.RunID, "state": result.State, "selling_allowed": false, "physical_acceptance": false}); err != nil {
		return 1
	}
	if result.State != "passed" {
		return 1
	}
	return 0
}
func macNativeInstallation(ctx context.Context, d nativeDeps, state, registrationSHA string) (nativeInstallation, error) {
	journalRaw, err := macRead(filepath.Join(state, "registration-"+registrationSHA+".json"), 0600, 2<<20)
	if err != nil {
		return nativeInstallation{}, err
	}
	var j registrationJournal
	if err = macDecode(journalRaw, &j); err != nil {
		return nativeInstallation{}, err
	}
	env, err := macRead(macPath(d.registration.root, "/etc/hypermesh/agent.env"), 0600, 2<<20)
	if err != nil {
		return nativeInstallation{}, err
	}
	config, err := macConfig(env, j.Issuer, j.Dashboard)
	if err != nil {
		return nativeInstallation{}, err
	}
	if macValidate(j, registrationSHA, config) != nil || j.State != "registered-inactive" {
		return nativeInstallation{}, fmt.Errorf("native certification requires the current inactive Mac registration")
	}
	check := func(ctx context.Context) error {
		current, hardware, e := macSnapshot(ctx, d.registration, config)
		if e != nil {
			return e
		}
		_, managed := nativeAutomatic(ctx)
		if e = validateMacNativeSnapshot(current, registrationSHA, hardware, j.Request.Hardware, managed); e != nil {
			return e
		}
		if e = macIdentity(d.registration, j, false); e != nil {
			return e
		}
		if e = macServices(ctx, d.registration, managed, false); e != nil {
			return e
		}
		if _, e = os.Lstat(macPath(d.registration.root, "/var/lib/hypermesh/lease.json")); !os.IsNotExist(e) {
			return fmt.Errorf("native certification requires no local lease")
		}
		return nil
	}
	return nativeInstallation{journal: j, plane: config.ControlPlane, tenant: config.Tenant, check: check}, nil
}

// The original registration digest includes installed binary bytes. For a
// running agent, the frozen Plane workload separately pins the collector build.
func validateMacNativeSnapshot(current, registered string, hardware, original hostregistration.Hardware, managed bool) error {
	if current == registered {
		return nil
	}
	hardware.ModelMemoryBytes = 0
	original.ModelMemoryBytes = 0
	if !managed || hardware != original {
		return fmt.Errorf("installed Mac configuration differs")
	}
	return nil
}

func printNativePlan(out io.Writer, path string, p nativePlan) int {
	if json.NewEncoder(out).Encode(map[string]any{"plan": path, "plan_sha256": nativePlanDigest(p), "run": p.Run}) != nil {
		return 1
	}
	return 0
}
func nativeEvidence(r certmeasure.Report, m hostregistration.NativeManifest) (hostregistration.NativeEvidence, error) {
	backend := "metal"
	if m.Protocol == hostregistration.NativeVulkanProtocol {
		backend = "vulkan"
	}
	e := hostregistration.NativeEvidence{EnvironmentHash: r.EnvironmentHash, Hardware: r.Hardware, FileHash: "sha256:" + r.ModelSHA256, RuntimeSHA256: r.RuntimeSHA256, CollectorCommit: r.CollectorCommit, OS: r.OS, Arch: r.Arch, StartedAt: r.StartedAt, CompletedAt: r.CompletedAt, CleanupComplete: true, Samples: []hostregistration.NativeSample{}}
	if m.Validate() != nil || r.Schema != "hypermesh-certification-measurements-v1" || r.MeasurementState != "passed" || r.FailureCode != "" || r.CertificationState != "not_evaluated" || r.PhysicalAcceptance || r.Backend != backend || r.Device != m.Device || r.RuntimeImage != "" || r.OS != m.OS || r.Arch != m.Arch || r.EnvironmentHash != m.EnvironmentHash || r.Hardware != m.Hardware || e.FileHash != m.FileHash || r.RuntimeSHA256 != m.RuntimeSHA256 || r.CollectorCommit != m.CollectorCommit || r.ContextTokens != m.ContextTokens || r.GeneratedTokens != 32 || len(r.Samples) != 3 || !r.CompletedAt.After(r.StartedAt) {
		return e, fmt.Errorf("native report differs from the approved protocol, pins or inventory")
	}
	for _, s := range r.Samples {
		var rows []struct {
			Average   float64   `json:"avg_ns"`
			Samples   []float64 `json:"samples_ns"`
			Prompt    *int      `json:"n_prompt"`
			Depth     *int      `json:"n_depth"`
			Generated *int      `json:"n_gen"`
			Layers    *int      `json:"n_gpu_layers"`
			Device    string    `json:"devices"`
			Backends  string    `json:"backends"`
			GPU       string    `json:"gpu_info"`
		}
		if json.Unmarshal(s.Raw, &rows) != nil || len(rows) != 1 {
			return e, fmt.Errorf("native raw context proof missing")
		}
		v := rows[0]
		reported := strings.ToLower(v.Backends)
		backendMatches := strings.Contains(reported, "mtl") || strings.Contains(reported, "metal")
		if backend == "vulkan" {
			backendMatches = false
			for _, name := range strings.Split(reported, ",") {
				if strings.TrimSpace(name) == "vulkan" {
					backendMatches = nativeVulkanGPUMatches(m.HardwareClassID, v.GPU)
					break
				}
			}
		}
		if v.Prompt == nil || *v.Prompt != 0 || v.Depth == nil || *v.Depth != m.ContextTokens-32 || v.Generated == nil || *v.Generated != 32 || v.Layers == nil || *v.Layers != 99 || v.Device != m.Device || !backendMatches || v.Average <= 0 || math.IsNaN(v.Average) || math.IsInf(v.Average, 0) || len(v.Samples) != 1 || v.Samples[0] != v.Average || math.Abs(s.TokensPerSecond-32e9/v.Average) > 1e-6 {
			return e, fmt.Errorf("native raw sample differs from requested native depth workload")
		}
		e.Samples = append(e.Samples, hostregistration.NativeSample{CapturedAt: s.CapturedAt, ElapsedMS: s.ElapsedMS, AverageNS: v.Average, PromptTokens: 0, DepthTokens: *v.Depth, GeneratedTokens: 32, GPULayers: 99, Device: v.Device, Backend: backend})
	}
	return e, nil
}

var nativeGPUWord = regexp.MustCompile(`[a-z0-9_]+`)

func nativeVulkanGPUMatches(class, gpu string) bool {
	words := make(map[string]bool)
	for _, word := range nativeGPUWord.FindAllString(strings.ToLower(gpu), -1) {
		words[word] = true
	}
	if !words["strix_halo"] {
		return false
	}
	switch class {
	case "amd-ryzen-ai-max-395":
		return words["8060s"] && !words["8065s"]
	case "amd-ryzen-ai-max-495":
		return words["8065s"] && !words["8060s"]
	default:
		return false
	}
}

// Preserve absence separately from a malformed or unsafe existing file.
func nativeRead(path string) ([]byte, error) {
	if err := macDirectory(filepath.Dir(path), false, false); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return macRead(path, 0600, 2<<20)
}

// Production calls require euid 0. The internal fixture root only bounds tests;
// it is not exposed as a CLI option. No writable/sticky directory exception is
// safe here: every component used to resolve the executable must be trusted.
func trustedNativeRuntime(path, fixtureRoot string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("native runtime requires an absolute canonical path")
	}
	if fixtureRoot != "" {
		rel, e := filepath.Rel(fixtureRoot, path)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("native runtime is outside the fixture root")
		}
	}
	for current := path; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil {
			return fmt.Errorf("native runtime or ancestor is unavailable")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native runtime and every ancestor must be root-owned and not writable by other users")
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return fmt.Errorf("native runtime must be a regular executable")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("native runtime ancestor must be a directory")
		}
		if current == "/" || current == fixtureRoot {
			return nil
		}
	}
}
