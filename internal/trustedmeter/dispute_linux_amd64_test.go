package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// This signer substitutes for Plane's archive API; it exercises Host's
// consumer contract, not durable owner storage (Plane #161).
func disputeProof(t *testing.T, owner ed25519.PrivateKey, result disputeArchiveResult) Signed {
	t.Helper()
	hash, err := Hash(map[string]string{"batch_id": result.BatchID, "runtime_key": result.RuntimeKey})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	b := binding()
	record := OwnerRecord{"owner-meter-v1", "archive-dispute", b.TenantID, b.LeaseID, b.GatewayID, hash, raw}
	encoded, err := canonicalValue(record)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{encoded, hex.EncodeToString(ed25519.Sign(owner, append([]byte(ownerDomain), encoded...)))}
}

func TestDisputeArchiveBindsFullHistoryAndOwnerAnchor(t *testing.T) {
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
	c.Outcome = "running"
	first, _ := Sign(c, key)
	if err := j.Append(batch, first); err != nil {
		t.Fatal(err)
	}
	firstHash, _ := Hash(c)
	c.Sequence++
	c.PreviousSHA256 = firstHash
	c.Counters.AcceptedOutput++
	second, _ := Sign(c, key)
	if err := j.Append(batch, second); err != nil {
		t.Fatal(err)
	}
	entry, _ := j.Status(binding(), batch)
	manifest, err := archiveManifest(binding(), pub, entry)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := Hash(manifest)
	// The final locally persisted record need not have reached the owner.
	good := disputeArchiveResult{batch, hex.EncodeToString(pub), hash, 1, firstHash, "disputed"}
	for _, kind := range []string{"signature", "runtime-key", "archive", "anchor", "future-anchor", "zero-anchor", "status", "batch", "binding", "changed-local-history"} {
		t.Run(kind, func(t *testing.T) {
			result := good
			switch kind {
			case "runtime-key":
				result.RuntimeKey = strings.Repeat("a", 64)
			case "archive":
				result.ArchiveSHA256 = strings.Repeat("a", 64)
			case "anchor":
				result.LastAnchorSHA256 = strings.Repeat("a", 64)
			case "future-anchor":
				result.LastAnchorSequence = 3
			case "zero-anchor":
				result.LastAnchorSequence = 0
			case "status":
				result.Status = "settled"
			case "batch":
				result.BatchID = start
			}
			request := retirement{batch, hex.EncodeToString(pub), "archive-dispute", disputeProof(t, ownerKey, result)}
			if kind == "signature" {
				request.Proof.Signature = strings.Repeat("0", 128)
			}
			if kind == "binding" {
				s.binding.DeviceID = start
				defer func() { s.binding = binding() }()
			}
			if kind == "changed-local-history" {
				changed := entry
				changed.Epoch = start
				if s.matchDisputeArchive(request, changed, good) == nil {
					t.Fatal("changed history accepted")
				}
				return
			}
			if s.retireHistory(request) == nil {
				t.Fatal("invalid archive accepted")
			}
			if _, err := os.Stat(j.path); err != nil {
				t.Fatal("history removed", err)
			}
		})
	}
	request := retirement{batch, hex.EncodeToString(pub), "archive-dispute", disputeProof(t, ownerKey, good)}
	if err := s.retireHistory(request); err != nil {
		t.Fatal(err)
	}
	if err := s.retireHistory(request); err != nil {
		t.Fatal("retry", err)
	}
	if _, err := os.Stat(j.path); !os.IsNotExist(err) {
		t.Fatal("history retained", err)
	}
}

func TestDisputedInterruptedStartsCanReleaseStorageWithoutSettlement(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{binding: binding(), key: key, owner: owner, stateDir: t.TempDir()}
	for n := 0; n < MaxLeaseJournalFiles+2; n++ {
		id := fmt.Sprintf("%08x-5555-5555-5555-555555555555", n)
		j, err := s.requestJournal(pub, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Begin(id, epoch); err != nil {
			t.Fatal(err)
		}
		// Cover loss before the start response as well as after a durable start.
		if n%2 == 0 {
			if err := j.Started(id, start); err != nil {
				t.Fatal(err)
			}
		}
		entry, _ := j.Status(binding(), id)
		manifest, err := archiveManifest(binding(), pub, entry)
		if err != nil {
			t.Fatal(err)
		}
		hash, _ := Hash(manifest)
		result := disputeArchiveResult{id, hex.EncodeToString(pub), hash, 0, strings.Repeat("0", 64), "disputed"}
		if err := s.retireHistory(retirement{id, result.RuntimeKey, "archive-dispute", disputeProof(t, ownerKey, result)}); err != nil {
			t.Fatal(n, err)
		}
	}
	entries, err := os.ReadDir(s.stateDir)
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	terminal := Entry{BatchID: batch, Epoch: epoch, StartID: start, Phase: "terminal"}
	manifest, _ := archiveManifest(binding(), pub, terminal)
	hash, _ := Hash(manifest)
	result := disputeArchiveResult{batch, hex.EncodeToString(pub), hash, 0, strings.Repeat("0", 64), "disputed"}
	if s.matchDisputeArchive(retirement{RuntimeKey: result.RuntimeKey}, terminal, result) == nil {
		t.Fatal("terminal bypassed recovery")
	}
}

func TestDisputeArchiveAllowsOnlyUnanchoredTerminalTail(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner, ownerKey, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{binding: binding(), key: key, owner: owner, stateDir: t.TempDir()}
	j, _ := s.requestJournal(pub, batch)
	if j.Begin(batch, epoch) != nil || j.Started(batch, start) != nil {
		t.Fatal("start")
	}
	final, _ := Sign(checkpoint(), key)
	if err := j.Append(batch, final); err != nil {
		t.Fatal(err)
	}
	entry, _ := j.Status(binding(), batch)
	manifest, _ := archiveManifest(binding(), pub, entry)
	hash, _ := Hash(manifest)
	tail, _ := Hash(final.Record)
	result := disputeArchiveResult{batch, hex.EncodeToString(pub), hash, 1, tail, "disputed"}
	if s.retireHistory(retirement{batch, result.RuntimeKey, "archive-dispute", disputeProof(t, ownerKey, result)}) == nil {
		t.Fatal("accepted terminal bypassed recovery")
	}
	result.LastAnchorSequence = 0
	result.LastAnchorSHA256 = strings.Repeat("0", 64)
	if err := s.retireHistory(retirement{batch, result.RuntimeKey, "archive-dispute", disputeProof(t, ownerKey, result)}); err != nil {
		t.Fatal(err)
	}
}
