package trustedmeter

import "strings"

var kernelRequired = []string{"64BIT", "X86_64", "AMD_MEM_ENCRYPT", "SEV_GUEST", "X86_MSR", "IKCONFIG", "IKCONFIG_PROC", "BLK_DEV_INITRD", "DEVTMPFS", "PROC_FS", "SYSFS", "TMPFS", "MEMFD_CREATE", "NET", "INET", "IP_PNP", "VIRTIO_PCI", "VIRTIO_NET", "NET_9P", "NET_9P_VIRTIO", "9P_FS", "NAMESPACES", "NET_NS", "IPC_NS", "UTS_NS", "PID_NS"}
var kernelForbidden = []string{"MODULES", "KEXEC", "KEXEC_FILE", "KEXEC_CORE", "DEVMEM", "DEVKMEM", "PROC_KCORE", "HIBERNATION", "SUSPEND", "DEBUG_FS", "USER_NS", "SWAP"}

func ValidateKernelConfig(config string) error {
	values := map[string]string{}
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, "CONFIG_") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return ErrInvalid
			}
			if _, exists := values[parts[0]]; exists {
				return ErrInvalid
			}
			values[parts[0]] = parts[1]
		}
	}
	for _, name := range kernelRequired {
		if values["CONFIG_"+name] != "y" {
			return ErrInvalid
		}
	}
	for _, name := range kernelForbidden {
		if value := values["CONFIG_"+name]; value != "" && value != "n" {
			return ErrInvalid
		}
	}
	return nil
}
