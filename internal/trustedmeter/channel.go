package trustedmeter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type ChannelRequest struct {
	Nonce      string `json:"nonce"`
	RuntimeKey string `json:"runtime_key"`
	GatewayKey string `json:"gateway_key"`
}
type ChannelResult struct {
	Binding    Binding `json:"binding"`
	RuntimeKey string  `json:"runtime_key"`
	GatewayKey string  `json:"gateway_key"`
	IssuedAt   *int64  `json:"issued_at"`
	Deadline   int64   `json:"deadline"`
}
type pendingChannel struct {
	request ChannelRequest
	before  time.Duration
	history *HistoryScope
}
type activeChannel struct {
	peer     string
	deadline time.Duration
	history  *HistoryScope
}

// Channels binds fresh owner authorizations to the actual TLS peer's Ed25519
// key. Certificate timestamps and names are not an authorization source here.
// The TLS stack must verify possession of that peer key during the handshake.
type Channels struct {
	mu             sync.Mutex
	binding        Binding
	runtime, owner ed25519.PublicKey
	clock          ProtectedClock
	drift          int64
	last           time.Duration
	failed         bool
	pending        map[string]pendingChannel
	active         map[string]activeChannel
}

func NewChannels(b Binding, runtime, owner ed25519.PublicKey, clock ProtectedClock, drift int64) (*Channels, error) {
	if b.Validate() != nil || len(runtime) != 32 || len(owner) != 32 || clock == nil || drift < 0 || drift > 10000 {
		return nil, ErrInvalid
	}
	return &Channels{binding: b, runtime: append(ed25519.PublicKey{}, runtime...), owner: append(ed25519.PublicKey{}, owner...), clock: clock, drift: drift, pending: map[string]pendingChannel{}, active: map[string]activeChannel{}}, nil
}
func (c *Channels) sample() (time.Duration, error) {
	if c.failed {
		return 0, ErrDisputed
	}
	now, err := c.clock.Sample()
	if err != nil || now < 0 || now < c.last || now > time.Duration(1<<63-1)-30*time.Second {
		c.failed = true
		return 0, ErrDisputed
	}
	c.last = now
	for nonce, p := range c.pending {
		if now-p.before >= 30*time.Second {
			delete(c.pending, nonce)
		}
	}
	for token, a := range c.active {
		if now >= a.deadline {
			delete(c.active, token)
		}
	}
	return now, nil
}
func randomHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (c *Channels) Challenge(peer ed25519.PublicKey) (ChannelRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(peer) != 32 {
		return ChannelRequest{}, ErrInvalid
	}
	before, err := c.sample()
	if err != nil {
		return ChannelRequest{}, err
	}
	if len(c.pending) >= 64 {
		return ChannelRequest{}, ErrDisputed
	}
	nonce, err := randomHex()
	if err != nil {
		return ChannelRequest{}, err
	}
	request := ChannelRequest{Nonce: nonce, RuntimeKey: hex.EncodeToString(c.runtime), GatewayKey: hex.EncodeToString(peer)}
	c.pending[nonce] = pendingChannel{request: request, before: before}
	return request, nil
}
func (c *Channels) Authorize(peer ed25519.PublicKey, nonce string, proof Signed) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.sample()
	if err != nil {
		return "", err
	}
	p, ok := c.pending[nonce]
	if !ok || p.history != nil || len(peer) != 32 || p.request.GatewayKey != hex.EncodeToString(peer) {
		return "", ErrInvalid
	}
	delete(c.pending, nonce)
	raw, err := VerifyOwner(proof, c.owner, c.binding, "channel", p.request)
	if err != nil {
		return "", err
	}
	var result ChannelResult
	if err = strict(raw, &result); err != nil {
		return "", err
	}
	if result.Binding != c.binding || result.RuntimeKey != p.request.RuntimeKey || result.GatewayKey != p.request.GatewayKey {
		return "", ErrInvalid
	}
	deadline, err := LocalDeadline(Grant{IssuedAt: result.IssuedAt, Deadline: result.Deadline}, p.before, now, c.drift)
	if err != nil {
		return "", err
	}
	if len(c.active) >= 64 {
		return "", ErrDisputed
	}
	token, err := randomHex()
	if err != nil {
		return "", err
	}
	c.active[token] = activeChannel{peer: hex.EncodeToString(peer), deadline: deadline}
	return token, nil
}
func (c *Channels) Check(peer ed25519.PublicKey, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.sample(); err != nil {
		return err
	}
	a, ok := c.active[token]
	if !ok || a.history != nil || len(peer) != 32 || a.peer != hex.EncodeToString(peer) {
		return ErrInvalid
	}
	return nil
}
