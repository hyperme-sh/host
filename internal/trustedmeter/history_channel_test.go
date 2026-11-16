package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func historyProof(t *testing.T, key ed25519.PrivateKey, request HistoryChannelRequest) Signed {
	t.Helper()
	issued := int64(1000)
	result := HistoryChannelResult{ChannelResult: ChannelResult{Binding: binding(), RuntimeKey: request.RuntimeKey, GatewayKey: request.GatewayKey, IssuedAt: &issued, Deadline: 1030}, HistoryScope: request.HistoryScope, Permissions: []string{"status", "retire"}}
	h, _ := Hash(request)
	raw, _ := json.Marshal(result)
	record := OwnerRecord{Kind: "owner-meter-v1", Operation: "history-channel", TenantID: binding().TenantID, LeaseID: binding().LeaseID, GatewayID: binding().GatewayID, RequestSHA256: h, Result: raw}
	raw, err := canonicalValue(record)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{raw, hex.EncodeToString(ed25519.Sign(key, append([]byte(ownerDomain), raw...)))}
}
func TestHistoryChannelCannotExecuteOrChangeJournal(t *testing.T) {
	owner, key, _ := ed25519.GenerateKey(rand.Reader)
	runtime, _, _ := ed25519.GenerateKey(rand.Reader)
	original, _, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	clock := &fakeClock{time.Second}
	c, _ := NewChannels(binding(), runtime, owner, clock, 1000)
	scope := HistoryScope{"11111111-1111-4111-8111-111111111111", hex.EncodeToString(original)}
	request, err := c.HistoryChallenge(peer, scope)
	if err != nil {
		t.Fatal(err)
	}
	proof := historyProof(t, key, request)
	if _, err = c.Authorize(peer, request.Nonce, proof); err == nil {
		t.Fatal("history nonce accepted by execution domain")
	}
	if _, err = c.HistoryAuthorize(other, request.Nonce, proof); err == nil {
		t.Fatal("wrong peer")
	}
	token, err := c.HistoryAuthorize(peer, request.Nonce, proof)
	if err != nil {
		t.Fatal(err)
	}
	if c.Check(peer, token) == nil {
		t.Fatal("history token can execute")
	}
	for _, op := range []string{"quote", "execute", "start", "renew"} {
		if c.CheckHistory(peer, token, op, scope.BatchID, scope.HistoricalRuntimeKey) == nil {
			t.Fatal(op)
		}
	}
	for _, op := range []string{"status", "retire"} {
		if err = c.CheckHistory(peer, token, op, scope.BatchID, scope.HistoricalRuntimeKey); err != nil {
			t.Fatal(err)
		}
		if c.CheckHistory(other, token, op, scope.BatchID, scope.HistoricalRuntimeKey) == nil {
			t.Fatal("wrong peer")
		}
		if c.CheckHistory(peer, token, op, "22222222-2222-4222-8222-222222222222", scope.HistoricalRuntimeKey) == nil {
			t.Fatal("wrong batch")
		}
		if c.CheckHistory(peer, token, op, scope.BatchID, request.RuntimeKey) == nil {
			t.Fatal("new guest replaced original identity")
		}
	}
	if _, err = c.HistoryAuthorize(peer, request.Nonce, proof); err == nil {
		t.Fatal("nonce replay")
	}
	ordinary, _ := c.Challenge(peer)
	if _, err = c.HistoryAuthorize(peer, ordinary.Nonce, channelProof(t, key, ordinary)); err == nil {
		t.Fatal("execution nonce accepted by history domain")
	}
	clock.now = 31 * time.Second
	if c.CheckHistory(peer, token, "status", scope.BatchID, scope.HistoricalRuntimeKey) == nil {
		t.Fatal("expired token")
	}
}
