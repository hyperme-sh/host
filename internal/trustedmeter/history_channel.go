package trustedmeter

import (
	"crypto/ed25519"
	"encoding/hex"
)

// HistoryScope identifies an immutable journal, never an execution grant.
type HistoryScope struct {
	BatchID              string `json:"batch_id"`
	HistoricalRuntimeKey string `json:"historical_runtime_key"`
}
type HistoryChannelRequest struct {
	ChannelRequest
	HistoryScope
}
type HistoryChannelResult struct {
	ChannelResult
	HistoryScope
	Permissions []string `json:"permissions"`
}

func (c *Channels) HistoryChallenge(peer ed25519.PublicKey, scope HistoryScope) (HistoryChannelRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(peer) != 32 || !uuidPattern.MatchString(scope.BatchID) || !digestPattern.MatchString(scope.HistoricalRuntimeKey) {
		return HistoryChannelRequest{}, ErrInvalid
	}
	before, err := c.sample()
	if err != nil {
		return HistoryChannelRequest{}, err
	}
	if len(c.pending) >= 64 {
		return HistoryChannelRequest{}, ErrDisputed
	}
	nonce, err := randomHex()
	if err != nil {
		return HistoryChannelRequest{}, err
	}
	request := ChannelRequest{Nonce: nonce, RuntimeKey: hex.EncodeToString(c.runtime), GatewayKey: hex.EncodeToString(peer)}
	c.pending[nonce] = pendingChannel{request: request, before: before, history: &scope}
	return HistoryChannelRequest{request, scope}, nil
}
func (c *Channels) HistoryAuthorize(peer ed25519.PublicKey, nonce string, proof Signed) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.sample()
	if err != nil {
		return "", err
	}
	p, ok := c.pending[nonce]
	if !ok || p.history == nil || len(peer) != 32 || p.request.GatewayKey != hex.EncodeToString(peer) {
		return "", ErrInvalid
	}
	delete(c.pending, nonce)
	raw, err := VerifyOwner(proof, c.owner, c.binding, "history-channel", HistoryChannelRequest{p.request, *p.history})
	if err != nil {
		return "", err
	}
	var result HistoryChannelResult
	if err = strict(raw, &result); err != nil {
		return "", err
	}
	if result.Binding != c.binding || result.RuntimeKey != p.request.RuntimeKey || result.GatewayKey != p.request.GatewayKey || result.HistoryScope != *p.history || len(result.Permissions) != 2 || result.Permissions[0] != "status" || result.Permissions[1] != "retire" {
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
	c.active[token] = activeChannel{peer: hex.EncodeToString(peer), deadline: deadline, history: p.history}
	return token, nil
}
func (c *Channels) CheckHistory(peer ed25519.PublicKey, token, operation, batch, runtime string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.sample(); err != nil {
		return err
	}
	a, ok := c.active[token]
	if !ok || a.history == nil || len(peer) != 32 || a.peer != hex.EncodeToString(peer) || (operation != "status" && operation != "retire") || a.history.BatchID != batch || a.history.HistoricalRuntimeKey != runtime {
		return ErrInvalid
	}
	return nil
}
