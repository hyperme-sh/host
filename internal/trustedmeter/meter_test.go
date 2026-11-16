package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func binding() Binding {
	return Binding{TenantID: "11111111-1111-1111-1111-111111111111", LeaseID: "22222222-2222-2222-2222-222222222222", DeviceID: "33333333-3333-3333-3333-333333333333", GatewayID: "44444444-4444-4444-4444-444444444444", ModelSHA256: strings.Repeat("a", 64), TokenizerSHA256: strings.Repeat("b", 64), TemplateSHA256: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64), Measurement: strings.Repeat("e", 96), PolicySHA256: PolicySHA256}
}

const batch = "55555555-5555-5555-5555-555555555555"
const epoch = "66666666-6666-6666-6666-666666666666"
const start = "77777777-7777-7777-7777-777777777777"

func TestCounterPolicy(t *testing.T) {
	c := Counters{5, 9, 7, 20, 30}
	n, e := c.Billable()
	if e != nil || n != 14 {
		t.Fatal(n, e)
	}
	for _, c := range []Counters{{AcceptedOutput: 1, HiddenOutput: 2}, {ProcessedInput: math.MaxInt64, AcceptedOutput: 1}, {CacheHits: -1}} {
		if _, e = c.Billable(); e == nil {
			t.Fatal(c)
		}
	}
	if _, e = (Counters{CacheHits: math.MaxInt64}).Add(Counters{CacheHits: 1}); e == nil {
		t.Fatal("overflow")
	}
}
func TestCanonicalRejectsAmbiguousRecords(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":1.0}`, `{"x":9223372036854775808}`, `{"x":-1}`, `{"x":"é"}`, `{} {}`} {
		if _, e := Canonical([]byte(s)); e == nil {
			t.Fatal(s)
		}
	}
	b, e := Canonical([]byte(`{ "z": true,"a":1}`))
	if e != nil || string(b) != `{"a":1,"z":true}` {
		t.Fatal(string(b), e)
	}
}
func TestSignatureDomainsAndNonce(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r, e := NewStart(binding(), epoch, batch)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Sign(r, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(s, pub, false); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(s, pub, true); e == nil {
		t.Fatal("cross-domain")
	}
	other, _ := NewStart(binding(), epoch, batch)
	if r.Nonce == other.Nonce {
		t.Fatal("nonce reused")
	}
	s.Record, _ = json.Marshal(other)
	if _, e = Verify(s, pub, false); e == nil {
		t.Fatal("modified request")
	}
}
func TestTimerRejectsDelayedReplyAndNeverReanchors(t *testing.T) {
	issued := int64(1000)
	g := Grant{IssuedAt: &issued, Deadline: 1030}
	limit, e := LocalDeadline(g, time.Second, 5*time.Second, 1000)
	if e != nil || limit >= 30*time.Second {
		t.Fatal(limit, e)
	}
	if _, e = LocalDeadline(g, time.Second, 31*time.Second, 1000); e == nil {
		t.Fatal("late grant")
	}
	g.Replayed = true
	if _, e = LocalDeadline(g, time.Second, 2*time.Second, 1000); e == nil {
		t.Fatal("replayed start")
	}
	g.Replayed = false
	g.IssuedAt = nil
	if _, e = LocalDeadline(g, time.Second, 2*time.Second, 0); e == nil {
		t.Fatal("legacy grant")
	}
}
func ownerSigned(t *testing.T, key ed25519.PrivateKey, b Binding, req any, result any) Signed {
	t.Helper()
	h, e := Hash(req)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(result)
	r := OwnerRecord{Kind: "owner-meter-v1", Operation: "start", TenantID: b.TenantID, LeaseID: b.LeaseID, GatewayID: b.GatewayID, RequestSHA256: h, Result: raw}
	encoded, e := canonicalValue(r)
	if e != nil {
		t.Fatal(e)
	}
	return Signed{encoded, hex.EncodeToString(ed25519.Sign(key, append([]byte(ownerDomain), encoded...)))}
}
func TestOwnerGrantBindsFreshRequestAndScope(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	req, _ := NewStart(binding(), epoch, batch)
	wire, _ := Sign(req, key)
	issued := int64(1000)
	g := Grant{StartID: start, IssuedAt: &issued, Deadline: 1030, MaxBillable: 100, MaxRecordOnly: 200}
	s := ownerSigned(t, key, binding(), wire, g)
	if _, e := VerifyGrant(s, pub, binding(), "start", wire, 100, 200); e != nil {
		t.Fatal(e)
	}
	req2, _ := NewStart(binding(), epoch, batch)
	wire2, _ := Sign(req2, key)
	if _, e := VerifyGrant(s, pub, binding(), "start", wire2, 100, 200); e == nil {
		t.Fatal("old response accepted for fresh nonce")
	}
	b := binding()
	b.LeaseID = batch
	if _, e := VerifyGrant(s, pub, b, "start", wire, 100, 200); e == nil {
		t.Fatal("wrong lease")
	}
	if _, e := VerifyGrant(s, pub, binding(), "start", wire, 101, 200); e == nil {
		t.Fatal("changed budget")
	}
}
func checkpoint() Checkpoint {
	return Checkpoint{Kind: "checkpoint-v1", Binding: binding(), Epoch: epoch, BatchID: batch, StartID: start, Sequence: 1, PreviousSHA256: strings.Repeat("0", 64), Counters: Counters{5, 9, 7, 20, 30}, Outcome: "completed"}
}
func TestJournalSurvivesRestartButNeverRestartsWork(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "counts.json")
	j, e := OpenJournal(path, binding(), pub)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Begin(batch, epoch); e != nil {
		t.Fatal(e)
	}
	if e = j.Started(batch, start); e != nil {
		t.Fatal(e)
	}
	record, _ := Sign(checkpoint(), key)
	if e = j.Append(batch, record); e != nil {
		t.Fatal(e)
	}
	restored, e := OpenJournal(path, binding(), pub)
	if e != nil {
		t.Fatal(e)
	}
	status, e := restored.Status(binding(), batch)
	if e != nil || status.Phase != "terminal" || status.Records[0].Signature != record.Signature {
		t.Fatal(status, e)
	}
	if e = restored.Begin("88888888-8888-8888-8888-888888888888", epoch); e == nil {
		t.Fatal("restart executed work")
	}
	b := binding()
	b.TenantID = batch
	if _, e = restored.Status(b, batch); e == nil {
		t.Fatal("cross-tenant")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), hex.EncodeToString(key)) {
		t.Fatal("private key persisted")
	}
}
func TestJournalCrashAfterStartRemainsDisputed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "counts.json")
	j, _ := OpenJournal(path, binding(), pub)
	if e := j.Begin(batch, epoch); e != nil {
		t.Fatal(e)
	}
	restored, e := OpenJournal(path, binding(), pub)
	if e != nil {
		t.Fatal(e)
	}
	s, e := restored.Status(binding(), batch)
	if e != nil || s.Phase != "starting" || len(s.Records) != 0 {
		t.Fatal(s, e)
	}
	if restored.Started(batch, start) == nil {
		t.Fatal("uncertain start resumed")
	}
}
func TestJournalRejectsForkAndCounterRegression(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	j, _ := OpenJournal(filepath.Join(t.TempDir(), "counts.json"), binding(), pub)
	j.Begin(batch, epoch)
	j.Started(batch, start)
	c := checkpoint()
	c.Outcome = "running"
	s, _ := Sign(c, key)
	if e := j.Append(batch, s); e != nil {
		t.Fatal(e)
	}
	next := c
	next.Sequence = 2
	next.PreviousSHA256, _ = Hash(c)
	next.Counters.ProcessedInput = 4
	s, _ = Sign(next, key)
	if j.Append(batch, s) == nil {
		t.Fatal("counter regression")
	}
	next.Counters = c.Counters
	next.PreviousSHA256 = strings.Repeat("f", 64)
	s, _ = Sign(next, key)
	if j.Append(batch, s) == nil {
		t.Fatal("fork")
	}
}

func TestPlanePythonCheckpointCompatibility(t *testing.T) {
	raw, e := os.ReadFile("testdata/plane-checkpoint.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		PublicKey string `json:"public_key"`
		Signed    Signed `json:"signed"`
		Hash      string `json:"record_sha256"`
		Canonical string `json:"canonical"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	pub, e := hex.DecodeString(v.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := Verify(v.Signed, pub, false)
	if e != nil || string(canonical) != v.Canonical {
		t.Fatal(string(canonical), e)
	}
	var c Checkpoint
	if e = strict(canonical, &c); e != nil || c.Validate() != nil {
		t.Fatal(e)
	}
	hash, e := Hash(c)
	if e != nil || hash != v.Hash {
		t.Fatal(hash, e)
	}
}
