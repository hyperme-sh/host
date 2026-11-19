package runtime

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestVulkanRenderNodeBindsOneAMDDevice(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	add := func(name, vendor, driver string) {
		t.Helper()
		path := filepath.Join(sys, name, "device")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "vendor"), []byte(vendor+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("/drivers", driver), filepath.Join(path, "driver")); err != nil {
			t.Fatal(err)
		}
	}
	add("card0", "0x1002", "amdgpu")
	add("renderD128", "0x8086", "i915")
	add("renderD129", "0x1002", "amdgpu")
	add("renderD130", "0x1002", "radeon")
	node := filepath.Join(dev, "renderD129")
	if got, err := findVulkanRenderNode(sys, dev, func(string) bool { return true }); err != nil || got != node {
		t.Fatalf("render node = %q, %v", got, err)
	}
	if _, err := findVulkanRenderNode(sys, dev, func(string) bool { return false }); err == nil {
		t.Fatal("accepted a missing device node")
	}
	add("renderD131", "0x1002", "amdgpu")
	if _, err := findVulkanRenderNode(sys, dev, func(string) bool { return true }); err == nil {
		t.Fatal("accepted ambiguous AMD devices")
	}
}

func TestVulkanManagedContainerStartAndStop(t *testing.T) {
	if !VulkanImageEnabled() {
		t.Skip("requires the Linux amd64 runtime selection")
	}
	t.Setenv("HYPERMESH_RUNTIME_IMAGE_REPOSITORIES", `["ghcr.io/ggml-org/llama.cpp"]`)
	const ref = "ghcr.io/ggml-org/llama.cpp:server-vulkan"
	const node = "/dev/dri/renderD129"
	gguf := filepath.Join(t.TempDir(), "weights.gguf")
	if err := os.WriteFile(gguf, []byte("GGUF"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	start := NewVulkan()
	start.renderNode = func() (string, error) { return node, nil }
	start.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected executable %q", name)
		}
		calls = append(calls, args)
		return []byte("container"), nil
	}
	spec := Spec{LeaseID: "halo-lease", CatalogID: "qwen", ImageDigest: ref, Runtime: "runc",
		HostPort: "8080", BindAddress: "10.1.0.4", GGUFPath: gguf, LlamaCtxSize: "32768"}
	handle, err := start.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if handle.Backend != BackendLlamaCppVulkan || handle.ContainerID != "container" || len(calls) != 3 {
		t.Fatalf("handle=%+v calls=%v", handle, calls)
	}
	args := calls[2]
	for _, want := range []string{"--runtime=runc", "--device=" + node + ":" + node + ":rw", "10.1.0.4:8080:8080",
		gguf + ":/models/model.gguf:ro", WorkloadNetworkName, "no-new-privileges:true", "--read-only",
		"LLAMA_ARG_CTX_SIZE=32768", "LLAMA_ARG_N_PARALLEL=1", "LLAMA_ARG_CONTEXT_SHIFT=0", ref} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing %q in %v", want, args)
		}
	}
	if !strings.Contains(args[len(args)-1], "--device Vulkan0 --n-gpu-layers 999") ||
		slices.Contains(args, "--runtime=nvidia") || slices.Contains(args, "--privileged") {
		t.Fatalf("wrong Vulkan launch: %v", args)
	}
	if err := start.Stop(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls[3], []string{"stop", "container"}) ||
		!slices.Equal(calls[4], []string{"rm", ContainerName(spec.LeaseID)}) {
		t.Fatalf("unexpected teardown: %v", calls[3:])
	}
	for _, refused := range []Spec{
		{LeaseID: spec.LeaseID, CatalogID: spec.CatalogID, Runtime: "nvidia", ImageDigest: ref, GGUFPath: gguf},
		{LeaseID: spec.LeaseID, CatalogID: spec.CatalogID, Runtime: "runc", ImageDigest: "ghcr.io/other/image@sha256:" + strings.Repeat("a", 64), GGUFPath: gguf},
	} {
		if _, err := start.Start(context.Background(), refused); err == nil || len(calls) != 5 {
			t.Fatalf("refused workload reached docker: err=%v calls=%v", err, calls)
		}
	}
}
