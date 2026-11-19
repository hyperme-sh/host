package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var renderNodeName = regexp.MustCompile(`^renderD[0-9]+$`)
var errVulkanRenderNode = errors.New("hypermesh: Vulkan requires exactly one usable AMD render node")
var vulkanDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Vulkan uses the managed container lifecycle and grants exactly one AMD render
// node. It never falls back to CUDA, ROCm, or a software Vulkan driver.
type Vulkan struct {
	*NVIDIA
	renderNode func() (string, error)
}

func NewVulkan() *Vulkan {
	return &Vulkan{NVIDIA: &NVIDIA{Docker: "docker"}, renderNode: systemVulkanRenderNode}
}

func (v *Vulkan) Start(ctx context.Context, spec Spec) (*Handle, error) {
	if !VulkanImageEnabled() {
		return nil, errors.New(FailReason(BackendLlamaCppVulkan))
	}
	if spec.Runtime != "runc" {
		return nil, errors.New("hypermesh: Vulkan lease runtime must be runc")
	}
	node, err := v.renderNode()
	if err != nil {
		return nil, err
	}
	return v.NVIDIA.start(ctx, spec, node)
}

func validateVulkanImage(ref string) error {
	repository, digest, pinned := strings.Cut(ref, "@")
	if !pinned {
		_, err := ChannelRef(ref)
		return err
	}
	if !vulkanDigest.MatchString(digest) {
		return ErrBareDigest
	}
	_, err := ChannelRef(repository + ":test")
	return err
}

func vulkanStartArgs(spec Spec, ref, node string) []string {
	// The loader can see only RADV and the one passed-through render device.
	// The upstream server image stores llama-server in /app rather than PATH.
	command := strings.Replace(llamaServerCommand, "exec llama-server ",
		"server=llama-server\nif [ -x /app/llama-server ]; then server=/app/llama-server; fi\n"+
			"exec \"$server\" --device Vulkan0 --n-gpu-layers 999 ", 1)
	spec.SingleSlot = true
	return containerStartArgs(spec, ref, command,
		"--runtime=runc",
		"--device="+node+":"+node+":rw",
		"-e", "VK_DRIVER_FILES=/usr/share/vulkan/icd.d/radeon_icd.x86_64.json",
		"-e", "VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/radeon_icd.x86_64.json")
}

func systemVulkanRenderNode() (string, error) {
	return findVulkanRenderNode("/sys/class/drm", "/dev/dri", func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	})
}

func findVulkanRenderNode(sysRoot, devRoot string, isCharDevice func(string) bool) (string, error) {
	nodes, err := os.ReadDir(sysRoot)
	if err != nil {
		return "", errVulkanRenderNode
	}
	var selected string
	for _, entry := range nodes {
		name := entry.Name()
		if !renderNodeName.MatchString(name) {
			continue
		}
		device := filepath.Join(sysRoot, name, "device")
		vendor, _ := os.ReadFile(filepath.Join(device, "vendor"))
		driver, _ := os.Readlink(filepath.Join(device, "driver"))
		node := filepath.Join(devRoot, name)
		if strings.TrimSpace(string(vendor)) != "0x1002" || filepath.Base(driver) != "amdgpu" || !isCharDevice(node) {
			continue
		}
		if selected != "" {
			return "", errVulkanRenderNode
		}
		selected = node
	}
	if selected == "" {
		return "", errVulkanRenderNode
	}
	return selected, nil
}

// VulkanModelBudget bounds downloads by the selected device's measured GTT
// or VRAM headroom and available system memory. The limits can describe the
// same physical RAM, so use the larger single pool rather than adding them.
func VulkanModelBudget(available int64) int64 {
	node, err := systemVulkanRenderNode()
	if err != nil {
		return 0
	}
	device := filepath.Join("/sys/class/drm", filepath.Base(node), "device")
	memory := min(available, max(freeDRMMemory(device, "gtt"), freeDRMMemory(device, "vram")))
	return max(0, memory-max(memory/4, 2<<30))
}

func freeDRMMemory(device, pool string) int64 {
	total, errTotal := readDRMMemory(device, pool+"_total")
	used, errUsed := readDRMMemory(device, pool+"_used")
	if errTotal != nil || errUsed != nil || used < 0 || used >= total {
		return 0
	}
	return total - used
}

func readDRMMemory(device, field string) (int64, error) {
	value, err := os.ReadFile(filepath.Join(device, "mem_info_"+field))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
}
