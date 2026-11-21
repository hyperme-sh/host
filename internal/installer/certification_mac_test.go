//go:build linux || darwin

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
	"testing"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

func nativeFixtureReport() (certmeasure.Report, hostregistration.NativeManifest) {
	now := time.Now().UTC()
	m := hostregistration.NativeManifest{InventoryEpoch: time.Now().UTC().Format(time.RFC3339Nano), SuiteID: "pack-v1", CatalogID: "mac-model", ClassID: macLabClass, Purpose: "native-certification-v1", Protocol: hostregistration.NativeMetalProtocol, FileHash: "sha256:" + strings.Repeat("a", 64), RuntimeSHA256: strings.Repeat("b", 64), CollectorCommit: strings.Repeat("d", 40), Device: "MTL0", EnvironmentHash: "sha256:" + strings.Repeat("e", 64), Hardware: strings.Repeat("f", 64), OS: "darwin", Arch: "arm64", Samples: 3, GeneratedTokens: 32, ContextTokens: 4096, DecodeTokS: 40, SizeBytes: 3}
	r := certmeasure.Report{Schema: "hypermesh-certification-measurements-v1", CollectorCommit: m.CollectorCommit, Device: m.Device, EnvironmentHash: m.EnvironmentHash, Hardware: m.Hardware, ModelSHA256: strings.TrimPrefix(m.FileHash, "sha256:"), RuntimeSHA256: m.RuntimeSHA256, OS: m.OS, Arch: m.Arch, Backend: "metal", ContextTokens: m.ContextTokens, GeneratedTokens: 32, StartedAt: now, CompletedAt: now.Add(3 * time.Second), MeasurementState: "passed", CertificationState: "not_evaluated"}
	for i := 0; i < 3; i++ {
		raw := json.RawMessage(`[{"avg_ns":800000000,"samples_ns":[800000000],"n_prompt":0,"n_depth":4064,"n_gen":32,"n_gpu_layers":99,"devices":"MTL0","backends":"MTL,BLAS"}]`)
		r.Samples = append(r.Samples, certmeasure.Sample{CapturedAt: now.Add(time.Duration(i) * time.Second), ElapsedMS: 900, TokensPerSecond: 40, Raw: raw})
	}
	return r, m
}
func TestNativeProofRejectsMismatchedRawReports(t *testing.T) {
	for _, mutation := range []string{"ok", "metal-spelling", "context", "cpu", "missing", "nan", "pins", "hardware", "failed", "raw"} {
		t.Run(mutation, func(t *testing.T) {
			r, m := nativeFixtureReport()
			switch mutation {
			case "metal-spelling":
				for i := range r.Samples {
					r.Samples[i].Raw = bytes.ReplaceAll(r.Samples[i].Raw, []byte("MTL,BLAS"), []byte("Metal,BLAS"))
				}
			case "context":
				r.ContextTokens = 512
			case "cpu":
				r.Device = "CPU"
			case "missing":
				r.Samples = r.Samples[:2]
			case "nan":
				r.Samples[0].Raw = json.RawMessage(`[{"avg_ns":"NaN"}]`)
			case "pins":
				r.RuntimeSHA256 = strings.Repeat("a", 64)
			case "hardware":
				r.Hardware = strings.Repeat("a", 64)
			case "failed":
				r.MeasurementState = "failed"
			case "raw":
				r.Samples[0].Raw = bytes.ReplaceAll(r.Samples[0].Raw, []byte(`"n_depth":4064`), []byte(`"n_depth":512`))
			}
			e, err := nativeEvidence(r, m)
			if (err == nil) != (mutation == "ok" || mutation == "metal-spelling") {
				t.Fatal(err)
			}
			if mutation == "ok" && (len(e.Samples) != 3 || e.Samples[0].DepthTokens != 4064 || !e.CleanupComplete) {
				t.Fatal(e)
			}
		})
	}
}

type fakeNativeRemote struct {
	planCalls, reportCalls int
	run                    hostregistration.NativeRun
	losePlan, loseReport   bool
}

func (f *fakeNativeRemote) PlanNativeCertification(_ context.Context, r hostregistration.Request, device, secret, id, env, hw string) (hostregistration.NativeRun, error) {
	f.planCalls++
	if f.run.RunID != "" && f.run.RunID != id {
		return hostregistration.NativeRun{}, fmt.Errorf("retry changed run")
	}
	_, m := nativeFixtureReport()
	no := false
	f.run = hostregistration.NativeRun{ProtocolVersion: 1, RunID: id, TenantID: macTestTenant, DeviceID: device, RequestID: r.RequestID, Manifest: m, ManifestSHA256: strings.Repeat("c", 64), State: "planned", ExpiresAt: time.Now().Add(time.Hour), SellingAllowed: &no}
	if f.losePlan {
		f.losePlan = false
		return hostregistration.NativeRun{}, fmt.Errorf("lost planning response")
	}
	return f.run, nil
}
func (f *fakeNativeRemote) PlanNativeReference(ctx context.Context, r hostregistration.Request, device, secret, id, env, hw string) (hostregistration.NativeRun, error) {
	run, err := f.PlanNativeCertification(ctx, r, device, secret, id, env, hw)
	run.Manifest.Purpose = hostregistration.NativeReferencePurpose
	run.Manifest.DecodeTokS = 0
	return run, err
}

func TestMacFirstReferenceFlagFreezesPlanPurpose(t *testing.T) {
	f := newMacFixture(t)
	if code, _, diag := f.run(); code != 0 {
		t.Fatal(diag)
	}
	_, manifest := nativeFixtureReport()
	t.Setenv("HYPERMESH_SOURCE_SHA", "")
	old := buildinfo.Commit
	buildinfo.Commit = manifest.CollectorCommit
	defer func() { buildinfo.Commit = old }()
	directory := filepath.Join(f.d.root, "reference")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "plan.json")
	remote := &fakeNativeRemote{}
	deps := nativeDeps{registration: f.d,
		inventory: func(context.Context) (string, string, error) { return manifest.EnvironmentHash, manifest.Hardware, nil },
		remote:    func(string, string) (nativeRemote, error) { return remote, nil }}
	args := []string{"--registration-plan-sha", f.journal(t).PlanSHA256, "--plan", path}
	var out, diag bytes.Buffer
	if code := runNativeCertification(context.Background(), append(args, "--first-reference"), &out, &diag, true, deps); code != 0 {
		t.Fatal(diag.String())
	}
	var current nativePlan
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &current) != nil || !current.FirstReference || current.Run == nil ||
		current.Run.Manifest.Purpose != hostregistration.NativeReferencePurpose || current.Run.Manifest.DecodeTokS != 0 {
		t.Fatal("native first-reference purpose was not retained")
	}
	if code := runNativeCertification(context.Background(), args, &out, &diag, true, deps); code == 0 {
		t.Fatal("accepted retry with a mismatched plan purpose")
	}
}

func (f *fakeNativeRemote) ReportNativeCertification(_ context.Context, r hostregistration.Request, device, secret string, run hostregistration.NativeRun, e hostregistration.NativeEvidence) (hostregistration.NativeRun, error) {
	f.reportCalls++
	if f.loseReport {
		f.loseReport = false
		return hostregistration.NativeRun{}, fmt.Errorf("lost upload response")
	}
	run.State = "passed"
	return run, nil
}
func TestNativePlanningAndUploadRetriesRetainIdentityAndWork(t *testing.T) {
	f := newMacFixture(t)
	if code, _, diag := f.run(); code != 0 {
		t.Fatal(diag)
	}
	j := f.journal(t)
	old := buildinfo.Commit
	buildinfo.Commit = strings.Repeat("d", 40)
	defer func() { buildinfo.Commit = old }()
	remote := &fakeNativeRemote{losePlan: true, loseReport: true}
	measureCalls := 0
	r, m := nativeFixtureReport()
	d := nativeDeps{registration: f.d, inventory: func(context.Context) (string, string, error) { return m.EnvironmentHash, m.Hardware, nil }, remote: func(string, string) (nativeRemote, error) { return remote, nil }, measure: func(_ context.Context, args []string, out, diag io.Writer) int {
		measureCalls++
		dir := filepath.Join(f.d.root, "artifacts", "run")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		path := filepath.Join(dir, "report.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(out, path)
		return 0
	}}
	os.Mkdir(filepath.Join(f.d.root, "native"), 0700)
	path := filepath.Join(f.d.root, "native", "plan.json")
	planArgs := []string{"--registration-plan-sha", j.PlanSHA256, "--plan", path}
	call := func(planning bool, args []string) (int, string, string) {
		var out, diag bytes.Buffer
		code := runNativeCertification(context.Background(), args, &out, &diag, planning, d)
		return code, out.String(), diag.String()
	}
	if code, _, diag := call(true, planArgs); code == 0 || !strings.Contains(diag, "lost planning response") {
		t.Fatal("unexpected planning response", code, diag)
	}
	raw, _ := os.ReadFile(path)
	var before nativePlan
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := call(true, planArgs); code != 0 {
		t.Fatal(diag)
	}
	raw, _ = os.ReadFile(path)
	var p nativePlan
	json.Unmarshal(raw, &p)
	if p.RunID != before.RunID || remote.planCalls != 2 {
		t.Fatal("planning identity changed")
	}
	model := filepath.Join(f.d.root, "model.gguf")
	os.WriteFile(model, []byte("abc"), 0600)
	binary := filepath.Join(f.d.root, "llama-bench")
	if err := os.WriteFile(binary, []byte("verified runtime fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	args := []string{"--plan", path, "--approve-plan", nativePlanDigest(p), "--model-file", model, "--runtime-file", binary, "--artifact-dir", filepath.Join(f.d.root, "artifacts"), "--run"}
	// A writable ancestor would permit swapping an already-hashed pathname.
	// Refuse it before invoking the workload or retaining upload evidence.
	if err := os.Chmod(f.d.root, 0777); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call(false, args); code == 0 {
		t.Fatal("writable runtime ancestor accepted")
	}
	if measureCalls != 0 || remote.reportCalls != 0 {
		t.Fatal("unsafe runtime reached execution or upload")
	}
	if err := os.Chmod(f.d.root, 0700); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call(false, args); code == 0 {
		t.Fatal("lost upload accepted")
	}
	if code, _, diag := call(false, args); code != 0 {
		t.Fatal(diag)
	}
	if measureCalls != 1 || remote.reportCalls != 2 {
		t.Fatalf("reran measurements: %d, uploads: %d", measureCalls, remote.reportCalls)
	}
	if code, _, diag := call(false, args); code != 0 {
		t.Fatal(diag)
	}
	f.loaded["com.fyberlabs.hypermesh-agent"] = true
	if code, _, _ := call(false, args); code == 0 {
		t.Fatal("loaded agent permitted")
	}
	if measureCalls != 1 {
		t.Fatal("workload restarted")
	}
	for _, secret := range []string{j.DeviceSecret, j.PrivateKey} {
		receipt, _ := os.ReadFile(path + ".result.json")
		if bytes.Contains(receipt, []byte(secret)) {
			t.Fatal("credential leaked")
		}
	}
}

func TestNativeRuntimeResolutionRequiresTrustedOwnershipAndModes(t *testing.T) {
	for _, kind := range []string{"trusted", "writable-file", "writable-ancestor", "file-symlink", "ancestor-symlink", "not-executable", "relative", "wrong-owner"} {
		t.Run(kind, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "runtime")
			if err = os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(directory, "llama-bench")
			if err = os.WriteFile(binary, []byte("runtime"), 0755); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "writable-file":
				err = os.Chmod(binary, 0775)
			case "writable-ancestor":
				err = os.Chmod(directory, 0777)
			case "file-symlink":
				err = os.Rename(binary, binary+".saved")
				if err == nil {
					err = os.Symlink(binary+".saved", binary)
				}
			case "ancestor-symlink":
				err = os.Rename(directory, directory+".saved")
				if err == nil {
					err = os.Symlink(directory+".saved", directory)
				}
			case "not-executable":
				err = os.Chmod(binary, 0600)
			case "relative":
				binary = "relative/llama-bench"
			case "wrong-owner":
				if os.Geteuid() != 0 {
					t.Skip("chown fixture requires root; Darwin tests cover mode and link rejection")
				}
				err = os.Chown(binary, 65534, -1)
			}
			if err != nil {
				t.Fatal(err)
			}
			got := trustedNativeRuntime(binary, root)
			if (got == nil) != (kind == "trusted") {
				t.Fatalf("%s: %v", kind, got)
			}
		})
	}
}

func TestNativeVulkanEvidenceBindsBothHaloClasses(t *testing.T) {
	for _, hardwareClass := range []string{"amd-ryzen-ai-max-395", "amd-ryzen-ai-max-495"} {
		t.Run(hardwareClass, func(t *testing.T) {
			r, m := nativeFixtureReport()
			m.ClassID, m.HardwareClassID = "amd-halo-vulkan-lab", hardwareClass
			m.Protocol, m.OS, m.Arch, m.Device = hostregistration.NativeVulkanProtocol, "linux", "amd64", "Vulkan0"
			r.OS, r.Arch, r.Device, r.Backend = m.OS, m.Arch, m.Device, "vulkan"
			for i := range r.Samples {
				raw := bytes.ReplaceAll(r.Samples[i].Raw, []byte("MTL0"), []byte("Vulkan0"))
				raw = bytes.ReplaceAll(raw, []byte("MTL,BLAS"), []byte("Vulkan,BLAS"))
				gpu := "AMD Radeon 8060S Graphics (RADV STRIX_HALO)"
				if hardwareClass == "amd-ryzen-ai-max-495" {
					gpu = "AMD Radeon 8065S (RADV STRIX_HALO)"
				}
				var rows []map[string]any
				if err := json.Unmarshal(raw, &rows); err != nil {
					t.Fatal(err)
				}
				rows[0]["gpu_info"] = gpu
				var err error
				r.Samples[i].Raw, err = json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
			}
			e, err := nativeEvidence(r, m)
			if err != nil || len(e.Samples) != 3 || e.Samples[0].Backend != "vulkan" || !e.CleanupComplete {
				t.Fatalf("valid Vulkan samples refused: %v", err)
			}
			for i := range r.Samples {
				original := append([]byte(nil), r.Samples[i].Raw...)
				for _, gpu := range []string{"", "AMD Radeon 8060S", "AMD Radeon 8065S", "AMD Radeon 18060S (RADV STRIX_HALO)", "AMD Radeon 8060S 8065S (RADV STRIX_HALO)", "AMD Radeon 8060S (RADV STRIX_HALO)", "AMD Radeon 8065S (RADV STRIX_HALO)"} {
					if hardwareClass == "amd-ryzen-ai-max-395" && gpu == "AMD Radeon 8060S (RADV STRIX_HALO)" || hardwareClass == "amd-ryzen-ai-max-495" && gpu == "AMD Radeon 8065S (RADV STRIX_HALO)" {
						continue
					}
					var rows []map[string]any
					if err := json.Unmarshal(original, &rows); err != nil {
						t.Fatal(err)
					}
					rows[0]["gpu_info"] = gpu
					var err error
					r.Samples[i].Raw, err = json.Marshal(rows)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := nativeEvidence(r, m); err == nil {
						t.Fatalf("accepted wrong GPU in sample %d: %q", i, gpu)
					}
				}
				r.Samples[i].Raw = original
			}
			r.Samples[0].Raw = bytes.ReplaceAll(r.Samples[0].Raw, []byte("Vulkan,BLAS"), []byte("CUDA"))
			if _, err := nativeEvidence(r, m); err == nil {
				t.Fatal("accepted non-Vulkan samples for Vulkan certification")
			}
		})
	}
}

func TestManagedMacNativeSnapshotAllowsUpdatedCollectorOnSameHardware(t *testing.T) {
	original := hostregistration.Hardware{CPU: "Apple M5 Pro", SystemMemoryBytes: 64 << 30, ModelMemoryBytes: 40 << 30}
	current := original
	current.ModelMemoryBytes = 36 << 30
	if err := validateMacNativeSnapshot("current", "registered", current, original, true); err != nil {
		t.Fatal(err)
	}
	if err := validateMacNativeSnapshot("current", "registered", current, original, false); err == nil {
		t.Fatal("manual path accepted a changed registration snapshot")
	}
	current.CPU = "Apple M5 Max"
	if err := validateMacNativeSnapshot("current", "registered", current, original, true); err == nil {
		t.Fatal("managed path accepted different hardware")
	}
}
