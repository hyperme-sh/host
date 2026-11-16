package trustedmeter

import (
	"context"
	"crypto/ed25519"
	"strings"
	"sync"
	"time"
)

// ProtectedClock must come from the independently qualified guest platform.
// An implementation backed by host wall time does not satisfy this contract.
type ProtectedClock interface{ Sample() (time.Duration, error) }

// Owner exchanges signed count protocol messages. It must not retry start with
// a new nonce or timer sample. A failed exchange leaves execution disputed.
type Owner interface {
	Exchange(context.Context, string, Signed) (Signed, error)
}

type Renewal struct {
	Start
	StartID  string `json:"start_id"`
	Sequence int    `json:"sequence"`
}

// Controller serializes a single request. It is protocol machinery, not a
// platform attester. Only the measured guest may supply its clock and engine.
type Controller struct {
	mu                         sync.Mutex
	binding                    Binding
	epoch, batch               string
	key                        ed25519.PrivateKey
	ownerKey                   ed25519.PublicKey
	owner                      Owner
	clock                      ProtectedClock
	journal                    *Journal
	drift                      int64
	maxBillable, maxRecordOnly int64
	startID                    string
	deadline, lastSample       time.Duration
	sequence, renewSequence    int
	previous                   string
	counts                     Counters
	pendingKind                string
	pendingCount               int64
	failed, terminal           bool
}

func NewController(b Binding, epoch, batch string, key ed25519.PrivateKey, ownerKey ed25519.PublicKey, owner Owner, clock ProtectedClock, journal *Journal, drift, maxBillable, maxRecordOnly int64) (*Controller, error) {
	if b.Validate() != nil || !uuidPattern.MatchString(epoch) || !uuidPattern.MatchString(batch) || len(key) != ed25519.PrivateKeySize || len(ownerKey) != ed25519.PublicKeySize || owner == nil || clock == nil || journal == nil || drift < 0 || drift > 10000 || maxBillable < 0 || maxRecordOnly < 0 {
		return nil, ErrInvalid
	}
	journal.mu.Lock()
	matches := journal.data.Binding == b && ed25519.PublicKey(journal.data.RuntimeKey).Equal(key.Public())
	journal.mu.Unlock()
	if !matches {
		return nil, ErrInvalid
	}
	return &Controller{binding: b, epoch: epoch, batch: batch, key: append(ed25519.PrivateKey{}, key...), ownerKey: append(ed25519.PublicKey{}, ownerKey...), owner: owner, clock: clock, journal: journal, drift: drift, maxBillable: maxBillable, maxRecordOnly: maxRecordOnly, previous: strings.Repeat("0", 64)}, nil
}
func (c *Controller) sample() (time.Duration, error) {
	n, e := c.clock.Sample()
	if e != nil || n < 0 || n < c.lastSample {
		c.failed = true
		return 0, ErrDisputed
	}
	c.lastSample = n
	return n, nil
}
func (c *Controller) live() error {
	if c.failed || c.terminal || c.startID == "" {
		return ErrDisputed
	}
	n, e := c.sample()
	if e != nil || n >= c.deadline {
		c.failed = true
		return ErrDisputed
	}
	return nil
}
func (c *Controller) Start(ctx context.Context) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if c.failed || c.startID != "" {
		return ErrDisputed
	}
	if err = c.journal.Begin(c.batch, c.epoch); err != nil {
		return err
	}
	request, err := NewStart(c.binding, c.epoch, c.batch)
	if err != nil {
		return err
	}
	signed, err := Sign(request, c.key)
	if err != nil {
		return err
	}
	before, err := c.sample()
	if err != nil {
		return err
	}
	answer, err := c.owner.Exchange(ctx, "start", signed)
	if err != nil {
		return err
	}
	g, err := VerifyGrant(answer, c.ownerKey, c.binding, "start", signed, c.maxBillable, c.maxRecordOnly)
	if err != nil {
		return err
	}
	now, err := c.sample()
	if err != nil {
		return err
	}
	c.deadline, err = LocalDeadline(g, before, now, c.drift)
	if err != nil {
		return err
	}
	if err = c.journal.Started(c.batch, g.StartID); err != nil {
		return err
	}
	c.startID = g.StartID
	return c.live()
}
func (c *Controller) Renew(ctx context.Context) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if err = c.live(); err != nil {
		return err
	}
	if c.pendingKind != "" || c.renewSequence >= 256 {
		return ErrDisputed
	}
	base, err := NewStart(c.binding, c.epoch, c.batch)
	if err != nil {
		return err
	}
	base.Kind = "renew-v2"
	request := Renewal{Start: base, StartID: c.startID, Sequence: c.renewSequence + 1}
	signed, err := Sign(request, c.key)
	if err != nil {
		return err
	}
	before, err := c.sample()
	if err != nil {
		return err
	}
	answer, err := c.owner.Exchange(ctx, "renew", signed)
	if err != nil {
		return err
	}
	// A late renewal cannot resurrect a locally expired grant.
	if err = c.live(); err != nil {
		return err
	}
	g, err := VerifyGrant(answer, c.ownerKey, c.binding, "renew", signed, c.maxBillable, c.maxRecordOnly)
	if err != nil {
		return err
	}
	hash, err := Hash(request)
	if err != nil {
		return err
	}
	if g.StartID != c.startID || g.Sequence != request.Sequence || g.SHA256 != hash {
		return ErrInvalid
	}
	now, err := c.sample()
	if err != nil {
		return err
	}
	c.deadline, err = LocalDeadline(g, before, now, c.drift)
	if err != nil {
		return err
	}
	c.renewSequence++
	return nil
}

// Permit allows at most one bounded engine step. The engine must report that
// step's completed counts before asking for another. Decode continuation has
// no additional charge; its accepted output was already counted.
func (c *Controller) Permit(kind string, count int64) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if err = c.live(); err != nil {
		return err
	}
	if c.pendingKind != "" || c.sequence >= 255 {
		return ErrDisputed
	}
	switch kind {
	case "input":
		if count < 1 || count > 32 {
			return ErrInvalid
		}
	case "output":
		if count != 1 {
			return ErrInvalid
		}
	case "decode":
		if count != 0 || c.counts.AcceptedOutput == 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	total, err := c.counts.Billable()
	if err != nil {
		return err
	}
	if count > c.maxBillable-total {
		return ErrDisputed
	}
	c.pendingKind = kind
	c.pendingCount = count
	return nil
}

// Decoded acknowledges a successful continuation decode. A failed or lost
// decode must use Dispute; it cannot manufacture an exact terminal count.
func (c *Controller) Decoded() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if err = c.live(); err != nil {
		return err
	}
	if c.pendingKind != "decode" {
		return ErrInvalid
	}
	c.pendingKind = ""
	return nil
}
func (c *Controller) Count(ctx context.Context, counts Counters) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if err = c.live(); err != nil {
		return err
	}
	delta := Counters{counts.ProcessedInput - c.counts.ProcessedInput, counts.AcceptedOutput - c.counts.AcceptedOutput, counts.HiddenOutput - c.counts.HiddenOutput, counts.CacheHits - c.counts.CacheHits, counts.RejectedSpeculative - c.counts.RejectedSpeculative}
	if _, err = counts.Billable(); err != nil {
		return err
	}
	if _, err = delta.Billable(); err != nil {
		return err
	}
	// This initial CPU profile has no cache or speculative decoder.
	if delta.CacheHits != 0 || delta.RejectedSpeculative != 0 {
		return ErrInvalid
	}
	if c.pendingKind == "input" {
		if delta.ProcessedInput != c.pendingCount || delta.AcceptedOutput != 0 {
			return ErrInvalid
		}
	} else if c.pendingKind == "output" {
		if delta.AcceptedOutput != 1 || delta.ProcessedInput != 0 {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	if err = c.anchor(ctx, counts, "running"); err != nil {
		return err
	}
	c.pendingKind = ""
	return nil
}
func (c *Controller) Finish(ctx context.Context, outcome string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if err != nil {
			c.failed = true
		}
	}()
	if err = c.live(); err != nil {
		return err
	}
	if c.pendingKind != "" || (outcome != "completed" && outcome != "interrupted" && outcome != "no_work") || (outcome == "no_work" && c.counts != (Counters{})) {
		return ErrInvalid
	}
	if err = c.anchor(ctx, c.counts, outcome); err != nil {
		return err
	}
	c.terminal = true
	return nil
}
func (c *Controller) anchor(ctx context.Context, counts Counters, outcome string) error {
	record := Checkpoint{Kind: "checkpoint-v1", Binding: c.binding, Epoch: c.epoch, BatchID: c.batch, StartID: c.startID, Sequence: c.sequence + 1, PreviousSHA256: c.previous, Counters: counts, Outcome: outcome}
	if err := record.Validate(); err != nil {
		return err
	}
	signed, err := Sign(record, c.key)
	if err != nil {
		return err
	}
	if err = c.journal.Append(c.batch, signed); err != nil {
		return err
	}
	answer, err := c.owner.Exchange(ctx, "checkpoint", signed)
	if err != nil {
		return err
	}
	raw, err := VerifyOwner(answer, c.ownerKey, c.binding, "checkpoint", signed)
	if err != nil {
		return err
	}
	var result struct {
		SHA256   string `json:"sha256"`
		Sequence int    `json:"sequence"`
	}
	if err = strict(raw, &result); err != nil {
		return err
	}
	hash, err := Hash(record)
	if err != nil {
		return err
	}
	if result.SHA256 != hash || result.Sequence != record.Sequence {
		return ErrInvalid
	}
	if err = c.live(); err != nil {
		return err
	}
	c.previous = hash
	c.sequence = record.Sequence
	c.counts = counts
	return nil
}
func (c *Controller) Dispute() { c.mu.Lock(); defer c.mu.Unlock(); c.failed = true }

// DecodeSigned is the bounded strict parser for owner HTTP responses.
func DecodeSigned(raw []byte) (Signed, error) { var s Signed; err := strict(raw, &s); return s, err }
