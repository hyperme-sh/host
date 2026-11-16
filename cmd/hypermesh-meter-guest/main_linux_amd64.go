// The measured initrd installs this binary as /init. No interactive shell,
// environment-supplied trust root, or ordinary-host execution path is provided.
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/FyberLabs/hypermesh-host/internal/trustedmeter"
	"golang.org/x/sys/unix"
)

func fail() {
	fmt.Fprintln(os.Stderr, "trusted meter guest refused startup")
	if os.Getpid() == 1 {
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	}
	os.Exit(1)
}
func mount(source, target, kind, data string, flags uintptr) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return unix.Mount(source, target, kind, flags, data)
}
func main() {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		fail()
	}
	_ = syscall.Umask(0077)
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) != nil {
		fail()
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		fail()
	}
	if mount("proc", "/proc", "proc", "hidepid=2", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != nil {
		fail()
	}
	if mount("sysfs", "/sys", "sysfs", "", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != nil {
		fail()
	}
	if mount("devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID) != nil {
		fail()
	}
	if mount("tmpfs", "/run", "tmpfs", "mode=0755", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != nil {
		fail()
	}
	if mount("input", "/input", "9p", "trans=virtio,version=9p2000.L", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != nil {
		fail()
	}
	if mount("journal", "/journal", "9p", "trans=virtio,version=9p2000.L", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC) != nil {
		fail()
	}
	configFile, err := os.Open("/proc/config.gz")
	if err != nil {
		fail()
	}
	compressed, err := gzip.NewReader(configFile)
	if err != nil {
		fail()
	}
	config, err := io.ReadAll(io.LimitReader(compressed, (1<<20)+1))
	compressed.Close()
	configFile.Close()
	if err != nil || len(config) > 1<<20 || trustedmeter.ValidateKernelConfig(string(config)) != nil {
		fail()
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		fail()
	}
	profile, err := trustedmeter.LoadGuestProfile("/etc/hypermesh-meter/profile.json")
	if err != nil {
		fail()
	}
	binding, err := trustedmeter.LoadBinding("/input/binding.json")
	if err != nil || profile.Matches(binding) != nil {
		fail()
	}
	guest, err := trustedmeter.NewGuest(binding)
	if err != nil {
		fail()
	}
	binary, err := os.Open("/usr/bin/hypermesh-counted-cpu")
	if err != nil {
		fail()
	}
	defer binary.Close()
	model, err := os.Open("/input/model.gguf")
	if err != nil {
		fail()
	}
	defer model.Close()
	template, err := os.Open("/etc/hypermesh-meter/template.txt")
	if err != nil {
		fail()
	}
	defer template.Close()
	server, err := trustedmeter.NewGuestServer(guest, profile.OwnerPublicKey(), trustedmeter.EngineFiles{Binary: binary, Model: model, Template: template}, "/journal", profile.DriftPPM)
	if err != nil {
		fail()
	}
	defer server.Close()
	listener, err := net.Listen("tcp4", ":8443")
	if err != nil {
		fail()
	}
	if err = server.Serve(listener); err != nil {
		fail()
	}
}
