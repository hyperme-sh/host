package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func retirementProof(t *testing.T, key ed25519.PrivateKey, operation, id string, result any) Signed {
	t.Helper()
	hash, _ := Hash(map[string]string{"batch_id": id})
	raw, _ := json.Marshal(result)
	b := binding()
	record := OwnerRecord{Kind: "owner-meter-v1", Operation: operation, TenantID: b.TenantID, LeaseID: b.LeaseID, GatewayID: b.GatewayID, RequestSHA256: hash, Result: raw}
	encoded, err := canonicalValue(record)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{encoded, hex.EncodeToString(ed25519.Sign(key, append([]byte(ownerDomain), encoded...)))}
}
func TestRetirementRequiresMatchingOwnerRecoveryAndAllowsSustainedUse(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{binding: binding(), key: key, owner: owner, stateDir: t.TempDir()}
	for n := 0; n < MaxLeaseJournalFiles+2; n++ {
		id := fmt.Sprintf("%08x-5555-5555-5555-555555555555", n)
		j, err := s.requestJournal(pub, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Begin(id, epoch) != nil || j.Started(id, start) != nil {
			t.Fatal("start")
		}
		c := checkpoint()
		c.BatchID = id
		final, _ := Sign(c, key)
		if err = j.Append(id, final); err != nil {
			t.Fatal(err)
		}
		hash, _ := Hash(final.Record)
		billable, _ := c.Counters.Billable()
		proof := retirementProof(t, ownerKey, "recover", id, map[string]any{"batch_id": id, "terminal_sha256": hash, "counters": c.Counters, "billable": billable, "policy_sha256": PolicySHA256})
		request := retirement{id, hex.EncodeToString(pub), "recover", proof}
		if n == 0 {
			bad := request
			bad.Proof.Signature = hex.EncodeToString(make([]byte, 64))
			if s.retireHistory(bad) == nil {
				t.Fatal("unsigned deletion")
			}
			bad = request
			bad.BatchID = batch
			if s.retireHistory(bad) == nil {
				t.Fatal("cross-request deletion")
			}
			if _, err = j.Status(binding(), id); err != nil {
				t.Fatal("history lost", err)
			}
		}
		if err = s.retireHistory(request); err != nil {
			t.Fatal(n, err)
		}
		if err = s.retireHistory(request); err != nil {
			t.Fatal("idempotent retirement", err)
		}
	}
	entries, err := os.ReadDir(s.stateDir)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}
func TestJournalQuotaKeepsStatusAndNeedsOwnerNoStartToFreeSpace(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{binding: binding(), key: key, owner: owner, stateDir: t.TempDir()}
	first := "00000000-5555-5555-5555-555555555555"
	for n := 0; n < MaxLeaseJournalFiles-1; n++ {
		id := fmt.Sprintf("%08x-5555-5555-5555-555555555555", n)
		j, err := s.requestJournal(pub, id)
		if err != nil {
			t.Fatal(err)
		}
		if err = j.Begin(id, epoch); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.requestJournal(pub, batch); err == nil {
		t.Fatal("unbounded files")
	}
	j, err := s.requestJournal(pub, first)
	if err != nil {
		t.Fatal("status lost", err)
	}
	if _, err = j.Status(binding(), first); err != nil {
		t.Fatal(err)
	}
	hash, _ := Hash(map[string]any{"kind": "owner-no-start-v1", "binding": binding(), "epoch": epoch, "batch_id": first, "counters": Counters{}, "outcome": "no_work"})
	proof := retirementProof(t, ownerKey, "cancel", first, map[string]string{"batch_id": first, "terminal_sha256": hash})
	if err = s.retireHistory(retirement{first, hex.EncodeToString(pub), "cancel", proof}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.requestJournal(pub, batch); err != nil {
		t.Fatal("quota not reclaimed", err)
	}
}
func TestJournalByteReservationsIncludeAtomicReplacementAndHostHistory(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "retained"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxLeaseJournalBytes - 2*MaxRequestJournalBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if reserveRequestJournal(dir) == nil {
		t.Fatal("missing replacement allowance")
	}
	state := t.TempDir()
	old := filepath.Join(state, "trusted-meter", "11111111-1111-1111-1111-111111111111", "journal")
	if err = os.MkdirAll(old, 0700); err != nil {
		t.Fatal(err)
	}
	f, err = os.Create(filepath.Join(old, "retained"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxHostJournalBytes - MaxLeaseJournalBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ReserveHostJournal(state, binding().LeaseID) == nil {
		t.Fatal("unbounded host history")
	}
}

func TestHistoricalRecoveryProofBindsOriginalKeyAndTerminal(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{binding: binding(), key: key, owner: owner, stateDir: t.TempDir()}
	j, err := s.requestJournal(pub, batch)
	if err != nil {
		t.Fatal(err)
	}
	if j.Begin(batch, epoch) != nil || j.Started(batch, start) != nil {
		t.Fatal("start")
	}
	c := checkpoint()
	final, _ := Sign(c, key)
	if err = j.Append(batch, final); err != nil {
		t.Fatal(err)
	}
	hash, _ := Hash(final.Record)
	billable, _ := c.Counters.Billable()
	result, _ := json.Marshal(map[string]any{"batch_id": batch, "terminal_sha256": hash, "counters": c.Counters, "billable": billable, "policy_sha256": PolicySHA256})
	requestHash, _ := Hash(map[string]string{"batch_id": batch, "runtime_key": hex.EncodeToString(pub), "terminal_sha256": hash})
	b := binding()
	raw, _ := canonicalValue(OwnerRecord{Kind: "owner-meter-v1", Operation: "history-recover", TenantID: b.TenantID, LeaseID: b.LeaseID, GatewayID: b.GatewayID, RequestSHA256: requestHash, Result: result})
	proof := Signed{raw, hex.EncodeToString(ed25519.Sign(ownerKey, append([]byte(ownerDomain), raw...)))}
	request := retirement{batch, hex.EncodeToString(pub), "history-recover", proof}
	wrong := request
	wrong.RuntimeKey = hex.EncodeToString(owner)
	if s.retireHistory(wrong) == nil {
		t.Fatal("wrong original key")
	}
	if err = s.retireHistory(request); err != nil {
		t.Fatal(err)
	}
	if err = s.retireHistory(request); err != nil {
		t.Fatal("lost acknowledgement", err)
	}
}
