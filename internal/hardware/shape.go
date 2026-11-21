package hardware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Shape is the stable hardware inventory sent to Plane. It excludes drivers,
// free memory, board serials, and host-specific identifiers.
type Shape struct {
	CPU         string   `json:"cpu"`
	GPUs        []string `json:"gpus"`
	MemoryBytes int64    `json:"memory_bytes"`
}

func DetectShape(ctx context.Context) *Shape {
	var shape Shape
	switch runtime.GOOS {
	case "linux":
		shape = linuxShape()
	case "darwin":
		shape.CPU = output(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
		shape.MemoryBytes, _ = strconv.ParseInt(output(ctx, "sysctl", "-n", "hw.memsize"), 10, 64)
		var display struct {
			GPUs []struct {
				Model string `json:"sppci_model"`
				Cores string `json:"sppci_cores"`
			} `json:"SPDisplaysDataType"`
		}
		if json.Unmarshal([]byte(output(ctx, "system_profiler", "SPDisplaysDataType", "-json")), &display) != nil {
			return nil
		}
		for _, gpu := range display.GPUs {
			if gpu.Cores == "" {
				shape.GPUs = append(shape.GPUs, gpu.Model)
			} else {
				shape.GPUs = append(shape.GPUs, gpu.Model+" "+gpu.Cores+" cores")
			}
		}
	case "windows":
		const inventory = `$ErrorActionPreference='Stop'; [PSCustomObject]@{
cpu=(@(Get-CimInstance Win32_Processor | ForEach-Object Name) -join ' + ');
gpus=@(Get-CimInstance Win32_VideoController | ForEach-Object Name);
memory_bytes=[int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
} | ConvertTo-Json -Compress`
		if json.Unmarshal([]byte(output(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", inventory)), &shape) != nil {
			return nil
		}
	default:
		return nil
	}
	if strings.TrimSpace(shape.CPU) == "" || len(shape.CPU) > 160 || shape.MemoryBytes <= 0 || len(shape.GPUs) > 32 {
		return nil
	}
	for _, gpu := range shape.GPUs {
		if strings.TrimSpace(gpu) == "" || len(gpu) > 160 {
			return nil
		}
	}
	if shape.GPUs == nil {
		shape.GPUs = []string{}
	}
	return &shape
}

func linuxShape() Shape {
	var shape Shape
	for _, line := range strings.Split(read("/proc/cpuinfo"), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "model name" {
			shape.CPU = strings.TrimSpace(value)
			break
		}
	}
	if compatible := read("/proc/device-tree/compatible"); compatible != "" {
		// The SoC separates ARM boards that expose generic CPU core names.
		fields := strings.Fields(compatible)
		soc := fields[len(fields)-1]
		shape.CPU = strings.TrimSpace(shape.CPU + " " + soc)
	}
	shape.MemoryBytes = meminfo(read("/proc/meminfo"), "MemTotal")
	const pciRoot = "/sys/bus/pci/devices"
	if devices, err := os.ReadDir(pciRoot); err == nil {
		for _, device := range devices {
			path := filepath.Join(pciRoot, device.Name())
			class := read(filepath.Join(path, "class"))
			if !strings.HasPrefix(class, "0x03") {
				continue
			}
			vendor := read(filepath.Join(path, "vendor"))
			model := read(filepath.Join(path, "device"))
			if vendor != "" && model != "" {
				shape.GPUs = append(shape.GPUs, "pci:"+vendor+":"+model)
			}
		}
	}
	const drmRoot = "/sys/class/drm"
	if devices, err := os.ReadDir(drmRoot); err == nil {
		for _, device := range devices {
			if !strings.HasPrefix(device.Name(), "renderD") {
				continue
			}
			compatible := read(filepath.Join(drmRoot, device.Name(), "device/of_node/compatible"))
			if compatible != "" && len(compatible) <= 160 {
				shape.GPUs = append(shape.GPUs, compatible)
			}
		}
	}
	return shape
}
