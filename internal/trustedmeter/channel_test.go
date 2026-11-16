package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func channelProof(t *testing.T, key ed25519.PrivateKey, request ChannelRequest) Signed {
	t.Helper()
	issued := int64(1000)
	result := ChannelResult{Binding: binding(), RuntimeKey: request.RuntimeKey, GatewayKey: request.GatewayKey, IssuedAt: &issued, Deadline: 1030}
	h, _ := Hash(request)
	raw, _ := json.Marshal(result)
	record := OwnerRecord{Kind: "owner-meter-v1", Operation: "channel", TenantID: binding().TenantID, LeaseID: binding().LeaseID, GatewayID: binding().GatewayID, RequestSHA256: h, Result: raw}
	raw, err := canonicalValue(record)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{raw, hex.EncodeToString(ed25519.Sign(key, append([]byte(ownerDomain), raw...)))}
}
func TestChannelRequiresFreshOwnerProofAndMatchingTLSKey(t *testing.T) {
	owner, key, _ := ed25519.GenerateKey(rand.Reader)
	runtime, _, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	clock := &fakeClock{time.Second}
	c, err := NewChannels(binding(), runtime, owner, clock, 1000)
	if err != nil {
		t.Fatal(err)
	}
	request, err := c.Challenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	proof := channelProof(t, key, request)
	if _, err = c.Authorize(other, request.Nonce, proof); err == nil {
		t.Fatal("wrong TLS peer")
	}
	token, err := c.Authorize(peer, request.Nonce, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Check(peer, token); err != nil {
		t.Fatal(err)
	}
	if c.Check(other, token) == nil {
		t.Fatal("token transferred to another TLS peer")
	}
	if _, err = c.Authorize(peer, request.Nonce, proof); err == nil {
		t.Fatal("nonce replay")
	}
	fresh, err := c.Challenge(peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Authorize(peer, fresh.Nonce, proof); err == nil {
		t.Fatal("old proof substituted")
	}
	clock.now = 31 * time.Second
	if c.Check(peer, token) == nil {
		t.Fatal("expired channel")
	}
}
func TestDelayedChannelAndClockRollbackRefuse(t *testing.T) {
	owner, key, _ := ed25519.GenerateKey(rand.Reader)
	runtime, _, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	clock := &fakeClock{time.Second}
	c, _ := NewChannels(binding(), runtime, owner, clock, 1000)
	request, _ := c.Challenge(peer)
	proof := channelProof(t, key, request)
	clock.now = 30 * time.Second
	if _, err := c.Authorize(peer, request.Nonce, proof); err == nil {
		t.Fatal("late proof")
	}
	clock.now = 0
	if _, err := c.Challenge(peer); err == nil {
		t.Fatal("clock rollback")
	}
	clock.now = time.Second
	if _, err := c.Challenge(peer); err == nil {
		t.Fatal("rollback latch reset")
	}
}
