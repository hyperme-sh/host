package trustedmeter

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// GuestProfile is embedded in the measured initrd. In particular, OwnerKey
// must never come from provider-writable launch data or environment variables.
type GuestProfile struct {
	OwnerKey        string `json:"owner_key"`
	ModelSHA256     string `json:"model_sha256"`
	TokenizerSHA256 string `json:"tokenizer_sha256"`
	TemplateSHA256  string `json:"template_sha256"`
	RuntimeSHA256   string `json:"runtime_sha256"`
	PolicySHA256    string `json:"policy_sha256"`
	DriftPPM        int64  `json:"drift_ppm"`
}

func (p GuestProfile) Validate() error {
	for _, hash := range []string{p.OwnerKey, p.ModelSHA256, p.TokenizerSHA256, p.TemplateSHA256, p.RuntimeSHA256} {
		if !digestPattern.MatchString(hash) || hash == strings.Repeat("0", 64) {
			return ErrInvalid
		}
	}
	if p.TokenizerSHA256 != p.ModelSHA256 || p.PolicySHA256 != PolicySHA256 || p.DriftPPM < 1 || p.DriftPPM > 10000 {
		return ErrInvalid
	}
	return nil
}
func (p GuestProfile) Matches(b Binding) error {
	if p.Validate() != nil || b.Validate() != nil || b.ModelSHA256 != p.ModelSHA256 || b.TokenizerSHA256 != p.TokenizerSHA256 || b.TemplateSHA256 != p.TemplateSHA256 || b.RuntimeSHA256 != p.RuntimeSHA256 || b.PolicySHA256 != p.PolicySHA256 {
		return ErrInvalid
	}
	return nil
}
func (p GuestProfile) OwnerPublicKey() ed25519.PublicKey {
	key, _ := hex.DecodeString(p.OwnerKey)
	return key
}
func LoadGuestProfile(path string) (GuestProfile, error) {
	var p GuestProfile
	raw, err := boundedFile(path, 16384)
	if err != nil {
		return p, err
	}
	if err = strict(raw, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func LoadBinding(path string) (Binding, error) {
	var b Binding
	raw, err := boundedFile(path, 16384)
	if err != nil {
		return b, err
	}
	if err = strict(raw, &b); err != nil {
		return b, err
	}
	return b, b.Validate()
}
func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}

type Bundle struct {
	Schema          int          `json:"schema"`
	Profile         GuestProfile `json:"profile"`
	Measurement     string       `json:"measurement"`
	FirmwareSHA256  string       `json:"firmware_sha256"`
	KernelSHA256    string       `json:"kernel_sha256"`
	InitrdSHA256    string       `json:"initrd_sha256"`
	CBitPos         int          `json:"cbitpos"`
	ReducedPhysBits int          `json:"reduced_phys_bits"`
	MemoryMiB       int          `json:"memory_mib"`
	TSCFrequencyKHz int64        `json:"tsc_frequency_khz"`
}

func LoadBundle(dir string, b Binding) (Bundle, error) {
	var bundle Bundle
	raw, err := boundedFile(filepath.Join(dir, "bundle.json"), 16384)
	if err != nil {
		return bundle, err
	}
	if err = strict(raw, &bundle); err != nil {
		return bundle, err
	}
	if bundle.Schema != 1 || bundle.Profile.Matches(b) != nil || bundle.Measurement != b.Measurement || bundle.CBitPos < 32 || bundle.CBitPos > 63 || bundle.ReducedPhysBits < 1 || bundle.ReducedPhysBits > 8 || bundle.MemoryMiB < 2048 || bundle.MemoryMiB > 32768 || bundle.TSCFrequencyKHz < 100000 || bundle.TSCFrequencyKHz > 10000000 {
		return bundle, ErrInvalid
	}
	for _, hash := range []string{bundle.FirmwareSHA256, bundle.KernelSHA256, bundle.InitrdSHA256} {
		if !digestPattern.MatchString(hash) {
			return bundle, ErrInvalid
		}
	}
	return bundle, nil
}

// LaunchArgs describes only the fixed confidential profile. Paths name staged
// copies checked against bundle digests. No debug, migration, accelerator,
// monitor, NVRAM store, host shell, or ordinary runtime fallback is supplied.
func LaunchArgs(bundle Bundle, boot, input, journal string, port int) ([]string, error) {
	if port < 1024 || port > 65535 {
		return nil, ErrInvalid
	}
	for _, path := range []string{boot, input, journal} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\x00\n\r") {
			return nil, ErrInvalid
		}
	}
	sev := fmt.Sprintf("sev-snp-guest,id=sev0,cbitpos=%d,reduced-phys-bits=%d,policy=0x30000,kernel-hashes=on,secure-tsc=on,tsc-frequency=%d", bundle.CBitPos, bundle.ReducedPhysBits, bundle.TSCFrequencyKHz)
	return []string{"-enable-kvm", "-machine", "q35,confidential-guest-support=sev0,memory-backend=mem0", "-object", fmt.Sprintf("memory-backend-memfd,id=mem0,size=%dM,share=off", bundle.MemoryMiB), "-object", sev, "-cpu", "host", "-smp", "1", "-m", fmt.Sprint(bundle.MemoryMiB), "-bios", filepath.Join(boot, "firmware.fd"), "-kernel", filepath.Join(boot, "kernel"), "-initrd", filepath.Join(boot, "initrd.cpio"), "-append", GuestCommandLine, "-nodefaults", "-no-reboot", "-display", "none", "-serial", "none", "-monitor", "none", "-netdev", fmt.Sprintf("user,id=net0,dns=10.0.2.3,hostfwd=tcp:127.0.0.1:%d-:8443", port), "-device", "virtio-net-pci,netdev=net0", "-virtfs", "local,path=" + input + ",mount_tag=input,security_model=none,readonly=on", "-virtfs", "local,path=" + journal + ",mount_tag=journal,security_model=none"}, nil
}

// The same literal must be used when independently computing the launch hash.
const GuestCommandLine = "init=/init console=ttyS0 loglevel=0 panic=-1 ip=10.0.2.15::10.0.2.2:255.255.255.0:hypermesh:eth0:off"

func MarshalBinding(b Binding) ([]byte, error) {
	if b.Validate() != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(b)
}
