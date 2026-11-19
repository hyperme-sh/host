package installer

import (
	"regexp"

	"github.com/FyberLabs/hypermesh-host/internal/hardware"
)

const haloMemoryMode = "uma-vulkan"

var halo395Processor = regexp.MustCompile(`(?i)\bRyzen AI Max\+ 395\b`)
var halo495Processor = regexp.MustCompile(`(?i)\bRyzen AI Max\+ PRO 495\b`)

func haloHardware(f hardware.Facts, systemBytes int64) bool {
	return f.Arch == "amd64" && !f.Tegra && ((halo395Processor.MatchString(f.Processor) && systemBytes >= 112*GiB) ||
		(halo495Processor.MatchString(f.Processor) && systemBytes >= 172*GiB))
}

func haloSetup(p Plan) bool {
	r := p.Resources.Resources
	return p.Hardware.Backend == "vulkan" && haloHardware(p.Hardware.Facts, r.SystemBytes) &&
		p.Resources.MemoryMode == haloMemoryMode && r.UMA && r.UMAAllocationBytes == 0 &&
		validUMARuntime(r.UMARuntime) && r.UMARuntime.Backend == "vulkan"
}
