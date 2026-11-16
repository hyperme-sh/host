package trustedmeter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct{ now time.Duration }

func (f *fakeClock) Sample() (time.Duration, error) { return f.now, nil }

type fakeOwner struct {
	advanceCheckpoint time.Duration
	key               ed25519.PrivateKey
	clock             *fakeClock
	calls             []string
	replay            bool
	delay             time.Duration
	fail              string
	journal           *Journal
	t                 *testing.T
}

func (f *fakeOwner) Exchange(ctx context.Context, operation string, request Signed) (Signed, error) {
	f.calls = append(f.calls, operation)
	if operation == f.fail {
		return Signed{}, errors.New("lost reply")
	}
	f.clock.now += f.delay
	issued := int64(1000)
	var result any = Grant{StartID: start, IssuedAt: &issued, Deadline: 1030, MaxBillable: 100, MaxRecordOnly: 200, Replayed: f.replay}
	if operation == "checkpoint" {
		f.clock.now += f.advanceCheckpoint
		f.advanceCheckpoint = 0
		var record Checkpoint
		if err := strict(request.Record, &record); err != nil {
			f.t.Fatal(err)
		}
		status, err := f.journal.Status(f.journal.data.Binding, batch)
		if err != nil || len(status.Records) != record.Sequence {
			f.t.Fatal("not durable before anchor", err)
		}
		hash, _ := Hash(record)
		result = map[string]any{"sha256": hash, "sequence": record.Sequence}
	}
	if operation == "renew" {
		var record Renewal
		if err := strict(request.Record, &record); err != nil {
			f.t.Fatal(err)
		}
		hash, _ := Hash(record)
		result = Grant{StartID: start, IssuedAt: &issued, Deadline: 1030, MaxBillable: 100, MaxRecordOnly: 200, SHA256: hash, Sequence: record.Sequence}
	}
	hash, _ := Hash(request)
	raw, _ := json.Marshal(result)
	record := OwnerRecord{Kind: "owner-meter-v1", Operation: operation, TenantID: binding().TenantID, LeaseID: binding().LeaseID, GatewayID: binding().GatewayID, RequestSHA256: hash, Result: raw}
	raw, err := canonicalValue(record)
	if err != nil {
		f.t.Fatal(err)
	}
	return Signed{raw, hex.EncodeToString(ed25519.Sign(f.key, append([]byte(ownerDomain), raw...)))}, nil
}
func controller(t *testing.T) (*Controller, *fakeOwner, *fakeClock) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	op, ok, _ := ed25519.GenerateKey(rand.Reader)
	j, err := OpenJournal(filepath.Join(t.TempDir(), "counts.json"), binding(), pub)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{time.Second}
	owner := &fakeOwner{key: ok, clock: clock, journal: j, t: t}
	c, err := NewController(binding(), epoch, batch, key, op, owner, clock, j, 1000, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	return c, owner, clock
}
func TestControllerAnchorsHiddenOutputAndFinal(t *testing.T) {
	c, owner, _ := controller(t)
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Permit("input", 5); err != nil {
		t.Fatal(err)
	}
	counts := Counters{ProcessedInput: 5}
	if err := c.Count(ctx, counts); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if err := c.Permit("output", 1); err != nil {
			t.Fatal(err)
		}
		counts.AcceptedOutput++
		if i < 7 {
			counts.HiddenOutput++
		}
		if err := c.Count(ctx, counts); err != nil {
			t.Fatal(err)
		}
		if i < 8 {
			if err := c.Permit("decode", 0); err != nil {
				t.Fatal(err)
			}
			if err := c.Decoded(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.Finish(ctx, "completed"); err != nil {
		t.Fatal(err)
	}
	n, _ := c.counts.Billable()
	if n != 14 {
		t.Fatal(n)
	}
	if len(owner.calls) != 12 {
		t.Fatal(owner.calls)
	}
	if c.Permit("output", 1) == nil {
		t.Fatal("work after terminal")
	}
	status, err := c.journal.Status(binding(), batch)
	if err != nil || status.Phase != "terminal" {
		t.Fatal(status, err)
	}
}
func TestControllerRefusesReplayedDelayedAndLostStarts(t *testing.T) {
	for _, mode := range []string{"replay", "delay", "lost"} {
		t.Run(mode, func(t *testing.T) {
			c, o, _ := controller(t)
			switch mode {
			case "replay":
				o.replay = true
			case "delay":
				o.delay = 30 * time.Second
			case "lost":
				o.fail = "start"
			}
			if c.Start(context.Background()) == nil {
				t.Fatal("unsafe start")
			}
			if c.Permit("input", 1) == nil {
				t.Fatal("work without start")
			}
			if c.Start(context.Background()) == nil || len(o.calls) != 1 {
				t.Fatal("start retry")
			}
		})
	}
}
func TestControllerStopsAfterAnchorLossAndClockRollback(t *testing.T) {
	for _, mode := range []string{"anchor", "rollback", "expiry", "mismatch"} {
		t.Run(mode, func(t *testing.T) {
			c, o, clock := controller(t)
			ctx := context.Background()
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if err := c.Permit("input", 5); err != nil {
				t.Fatal(err)
			}
			counts := Counters{ProcessedInput: 5}
			switch mode {
			case "anchor":
				o.fail = "checkpoint"
			case "rollback":
				clock.now = 0
			case "expiry":
				clock.now = 31 * time.Second
			case "mismatch":
				counts.ProcessedInput = 6
			}
			if c.Count(ctx, counts) == nil {
				t.Fatal("unsafe count")
			}
			if c.Permit("output", 1) == nil || c.Finish(ctx, "completed") == nil {
				t.Fatal("work after uncertainty")
			}
		})
	}
}
func TestControllerRenewalCannotResurrectExpiredGrant(t *testing.T) {
	c, o, clock := controller(t)
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	clock.now = 10 * time.Second
	if err := c.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	clock.now = c.deadline - time.Second
	o.delay = 2 * time.Second
	if c.Renew(ctx) == nil {
		t.Fatal("late renewal")
	}
	if c.Permit("input", 1) == nil {
		t.Fatal("expired work")
	}
}
func TestControllerEnforcesBudgetAndPendingDecode(t *testing.T) {
	c, _, _ := controller(t)
	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{32, 32, 32, 4} {
		if err := c.Permit("input", n); err != nil {
			t.Fatal(err)
		}
		if err := c.Count(ctx, Counters{ProcessedInput: c.counts.ProcessedInput + n}); err != nil {
			t.Fatal(err)
		}
	}
	if c.Permit("output", 1) == nil {
		t.Fatal("exceeded finite budget")
	}
	c, _, _ = controller(t)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Permit("output", 1); err != nil {
		t.Fatal(err)
	}
	if c.Finish(ctx, "no_work") == nil {
		t.Fatal("pending work declared zero")
	}
}
func TestJournalRejectsAmbiguousEnvelope(t *testing.T) {
	for _, mode := range []string{"duplicate", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := controller(t)
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(c.journal.path)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "trailing" {
				raw = append(raw, []byte(" {}")...)
			} else {
				raw = append([]byte(`{"entries":{},`), raw[1:]...)
			}
			if err = os.WriteFile(c.journal.path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenJournal(c.journal.path, binding(), c.key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("ambiguous journal")
			}
		})
	}
}
