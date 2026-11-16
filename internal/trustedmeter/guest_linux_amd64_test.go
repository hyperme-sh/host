package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestQuoteDataBindsGuestKeyWorkloadAndFreshChallenge(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	a := Attestation{Kind: "attestation-v1", Issuer: "independent", Binding: binding(), Nonce: strings.Repeat("a", 64), RuntimeKey: hex.EncodeToString(pub), IssuedAt: 1000, ExpiresAt: 1060, Platform: "sev-snp-cpu", ChainValid: true, TCBCurrent: true, RevocationChecked: true, DebugDisabled: true, WorkloadMeasured: true, ProtectedTime: true, RollbackProtected: true}
	first, err := attestationData(a, binding(), pub)
	if err != nil {
		t.Fatal(err)
	}
	a.Nonce = strings.Repeat("b", 64)
	second, err := attestationData(a, binding(), pub)
	if err != nil || first == second {
		t.Fatal("nonce not bound", err)
	}
	a.RuntimeKey = strings.Repeat("c", 64)
	if _, err = attestationData(a, binding(), pub); err == nil {
		t.Fatal("substituted guest key")
	}
	a.RuntimeKey = hex.EncodeToString(pub)
	a.Binding.ModelSHA256 = strings.Repeat("f", 64)
	if _, err = attestationData(a, binding(), pub); err == nil {
		t.Fatal("substituted model")
	}
	a.Binding = binding()
	a.ProtectedTime = false
	if _, err = attestationData(a, binding(), pub); err == nil {
		t.Fatal("unprotected time")
	}
}
