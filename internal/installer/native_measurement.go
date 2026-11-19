package installer

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/certmeasure"
	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

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
		if v.Prompt == nil || *v.Prompt != 0 || v.Depth == nil || *v.Depth != m.ContextTokens-32 || v.Generated == nil || *v.Generated != 32 || v.Layers == nil || *v.Layers != 99 || v.Device != m.Device || !nativeBackendMatches(m.VulkanHardwareClass(), backend, v.Backends, v.GPU) || v.Average <= 0 || math.IsNaN(v.Average) || math.IsInf(v.Average, 0) || len(v.Samples) != 1 || v.Samples[0] != v.Average || math.Abs(s.TokensPerSecond-32e9/v.Average) > 1e-6 {
			return e, fmt.Errorf("native raw sample differs from requested native depth workload")
		}
		e.Samples = append(e.Samples, hostregistration.NativeSample{CapturedAt: s.CapturedAt, ElapsedMS: s.ElapsedMS, AverageNS: v.Average, PromptTokens: 0, DepthTokens: *v.Depth, GeneratedTokens: 32, GPULayers: 99, Device: v.Device, Backend: backend})
	}
	return e, nil
}

func nativeBackendMatches(class, backend, backends, gpu string) bool {
	if backend == "metal" {
		return strings.Contains(strings.ToLower(backends), "mtl") ||
			strings.Contains(strings.ToLower(backends), "metal")
	}
	if !strings.Contains(strings.ToLower(backends), "vulkan") ||
		!strings.Contains(strings.ToLower(gpu), "strix_halo") {
		return false
	}
	switch class {
	case "amd-ryzen-ai-max-395":
		return strings.Contains(gpu, "8060S")
	case "amd-ryzen-ai-max-495":
		return strings.Contains(gpu, "8065S")
	default:
		return false
	}
}
