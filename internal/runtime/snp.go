package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/trustedmeter"
)

const BackendSNP = "sev-snp-cpu"

var ErrTrustedRuntime = errors.New("trusted CPU runtime unavailable")

type SNP struct {
	BundleDir, StateDir string
	Run                 func(context.Context, string, ...string) ([]byte, error)
}

func NewSNP(bundleDir, stateDir string) *SNP { return &SNP{BundleDir: bundleDir, StateDir: stateDir} }
func (s *SNP) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.Run != nil {
		return s.Run(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
func (s *SNP) Start(ctx context.Context, spec Spec) (*Handle, error) {
	b := spec.TrustedMeter
	if !SNPEnabled() || s.BundleDir == "" || b == nil || b.Validate() != nil || spec.LeaseID != b.LeaseID || spec.Runtime != BackendSNP || spec.Backend != BackendSNP {
		return nil, ErrTrustedRuntime
	}
	unit := "hypermesh-meter-" + b.LeaseID
	if _, err := s.run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit); err == nil {
		return nil, ErrTrustedRuntime
	}
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrTrustedRuntime
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	hash, err := trustedmeter.Hash(*b)
	if err != nil {
		return nil, ErrTrustedRuntime
	}
	var instance [16]byte
	if _, err = rand.Read(instance[:]); err != nil {
		return nil, ErrTrustedRuntime
	}
	// Keep a cleanup handle from the first possible staging write. A launch
	// command can fail after creating a unit, so only Stop may remove files.
	handle := &Handle{ContainerID: "snp-" + hex.EncodeToString(instance[:]), Name: unit, LeaseID: b.LeaseID, CatalogID: spec.CatalogID, Backend: BackendSNP, FileHash: "sha256:" + b.ModelSHA256, State: HandleStarting, TrustedMeterBindingSHA256: hash, TrustedMeterDial: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	bundle, args, err := trustedmeter.PrepareLaunch(s.BundleDir, s.StateDir, *b, spec.GGUFPath, port)
	if err != nil {
		return handle, ErrTrustedRuntime
	}
	handle.TrustedMeterBundleSHA256 = bundle.InitrdSHA256
	command := []string{"--quiet", "--collect", "--unit=" + unit, "--property=KillMode=control-group", "--property=Restart=no", "--property=UMask=0077", "--property=LimitCORE=0", "--", "/usr/bin/qemu-system-x86_64"}
	command = append(command, args...)
	if _, err = s.run(ctx, "/usr/bin/systemd-run", command...); err != nil {
		return handle, ErrTrustedRuntime
	}
	return handle, nil
}
func (s *SNP) Stop(ctx context.Context, h *Handle) error {
	if h == nil || h.Backend != BackendSNP {
		return ErrTrustedRuntime
	}
	if _, err := trustedmeter.LeaseDirectory(s.StateDir, h.LeaseID); err != nil {
		return ErrTrustedRuntime
	}
	if _, err := s.run(ctx, "/usr/bin/systemctl", "stop", "hypermesh-meter-"+h.LeaseID); err != nil {
		status, _ := s.run(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,MainPID,ControlPID", "hypermesh-meter-"+h.LeaseID)
		if !confirmedStoppedUnit(string(status)) {
			return ErrTrustedRuntime
		}
	}
	return trustedmeter.CleanStoppedLaunch(s.StateDir, h.LeaseID)
}
func ValidTrustedDial(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1024 && number <= 65535 && !strings.ContainsAny(address, "\r\n")
}

func confirmedStoppedUnit(raw string) bool {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return false
		}
		if _, duplicate := fields[pair[0]]; duplicate {
			return false
		}
		fields[pair[0]] = pair[1]
	}
	if len(fields) != 4 || fields["MainPID"] != "0" || fields["ControlPID"] != "0" {
		return false
	}
	return fields["LoadState"] == "not-found" && fields["ActiveState"] == "inactive" || fields["LoadState"] == "loaded" && (fields["ActiveState"] == "inactive" || fields["ActiveState"] == "failed")
}
