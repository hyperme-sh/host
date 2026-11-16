package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"sync"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
)

type Attestation struct {
	Kind              string  `json:"kind"`
	Issuer            string  `json:"issuer"`
	Binding           Binding `json:"binding"`
	Nonce             string  `json:"nonce"`
	RuntimeKey        string  `json:"runtime_key"`
	IssuedAt          int64   `json:"issued_at"`
	ExpiresAt         int64   `json:"expires_at"`
	Platform          string  `json:"platform"`
	ChainValid        bool    `json:"chain_valid"`
	TCBCurrent        bool    `json:"tcb_current"`
	RevocationChecked bool    `json:"revocation_checked"`
	DebugDisabled     bool    `json:"debug_disabled"`
	WorkloadMeasured  bool    `json:"workload_measured"`
	ProtectedTime     bool    `json:"protected_time"`
	RollbackProtected bool    `json:"rollback_protected"`
}

// Guest keeps a fresh private key only in guest memory. It has no key export or
// disk sealing API. The measured boot profile must disable swap and debugging.
// Constructor checks do not replace independent validation of the SNP report.
type Guest struct {
	mu      sync.Mutex
	binding Binding
	key     ed25519.PrivateKey
	clock   *SNPClock
}

func NewGuest(b Binding) (*Guest, error) {
	if b.Validate() != nil {
		return nil, ErrInvalid
	}
	clock, err := NewSNPClock()
	if err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	g := &Guest{binding: b, key: key, clock: clock}
	// Fail before exposing this guest if its real hardware report disagrees.
	if _, err = g.quote([64]byte{}); err != nil {
		return nil, err
	}
	return g, nil
}
func (g *Guest) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey{}, g.key.Public().(ed25519.PublicKey)...)
}
func (g *Guest) quote(data [64]byte) ([]byte, error) {
	if _, err := g.clock.Sample(); err != nil {
		return nil, err
	}
	device := &client.LinuxDevice{}
	// Never use library testing flags, fake providers or caller-supplied paths.
	if err := device.Open("/dev/sev-guest"); err != nil {
		return nil, ErrDisputed
	}
	defer device.Close()
	raw, err := client.GetRawReportAtVmpl(device, data, 0)
	if err != nil {
		return nil, ErrDisputed
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	if report.GetVmpl() != 0 || report.GetPolicy()&(1<<18|1<<19) != 0 || hex.EncodeToString(report.GetMeasurement()) != g.binding.Measurement || hex.EncodeToString(report.GetReportData()) != hex.EncodeToString(data[:]) {
		return nil, ErrDisputed
	}
	return raw, nil
}
func attestationData(a Attestation, b Binding, key ed25519.PublicKey) ([64]byte, error) {
	var zero [64]byte
	if a.Kind != "attestation-v1" || len(a.Issuer) < 1 || len(a.Issuer) > 128 || a.Binding != b || !digestPattern.MatchString(a.Nonce) || a.RuntimeKey != hex.EncodeToString(key) || a.IssuedAt < 0 || a.ExpiresAt <= a.IssuedAt || a.ExpiresAt-a.IssuedAt > 60 || a.Platform != "sev-snp-cpu" || !a.ChainValid || !a.TCBCurrent || !a.RevocationChecked || !a.DebugDisabled || !a.WorkloadMeasured || !a.ProtectedTime || !a.RollbackProtected {
		return zero, ErrInvalid
	}
	raw, err := canonicalValue(a)
	if err != nil {
		return zero, err
	}
	return sha512.Sum512(append([]byte("hypermesh-snp-meter-v1\x00"), raw...)), nil
}

// Quote binds the candidate statement to the guest key. The independent issuer
// must validate the report and each statement before signing it; quoting the
// statement does not establish chain, revocation, or workload trust locally.
func (g *Guest) Quote(a Attestation) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	data, err := attestationData(a, g.binding, g.PublicKey())
	if err != nil {
		return nil, err
	}
	return g.quote(data)
}
func (g *Guest) Controller(epoch, batch string, ownerKey ed25519.PublicKey, owner Owner, journal *Journal, drift, maxBillable, maxRecordOnly int64) (*Controller, error) {
	return NewController(g.binding, epoch, batch, g.key, ownerKey, owner, g.clock, journal, drift, maxBillable, maxRecordOnly)
}
