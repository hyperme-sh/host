//go:build linux || darwin

package machineidentity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errUnauthorized = errors.New("machine identity proof rejected")

type Provider struct {
	Authority string
	Path      string
	HTTP      *http.Client
	Now       func() time.Time
}
type state struct {
	Schema    int    `json:"schema"`
	Renewal   string `json:"renewal_url"`
	Authority string `json:"authority_id"`
	Plane     string `json:"control_plane_id"`
	Base      string `json:"base"`
	Tenant    string `json:"tenant"`
	Device    string `json:"device"`
	Request   string `json:"request"`
	Key       string `json:"key"`
	Pending   string `json:"pending,omitempty"`
	Bound     bool   `json:"bound"`
	Created   int64  `json:"created"`
	Token     string `json:"token,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
}

func (state) String() string   { return "[private machine identity]" }
func (state) GoString() string { return "[private machine identity]" }
func newKey() (string, error) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(key), e
}
func private(value string) (ed25519.PrivateKey, error) {
	raw, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid saved machine key")
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !bytes.Equal(key, raw) {
		return nil, fmt.Errorf("inconsistent saved machine key")
	}
	return key, nil
}
func public(value string) string {
	key, _ := private(value)
	if key == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

type proof struct {
	Protocol  int    `json:"protocol_version"`
	Authority string `json:"authority_id"`
	Plane     string `json:"control_plane_id"`
	Request   string `json:"request_id"`
	Device    string `json:"device_id"`
	Nonce     string `json:"nonce"`
	Public    string `json:"public_key"`
	Issued    int64  `json:"issued_at"`
	Signature string `json:"signature"`
	Next      string `json:"next_public_key"`
}
type tokenReply struct {
	Token   string `json:"access_token"`
	Type    string `json:"token_type"`
	TTL     int64  `json:"expires_in"`
	Public  string `json:"public_key"`
	Created int64  `json:"key_created_at"`
}

func signed(s state, key, next string, now time.Time) (proof, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return proof{}, e
	}
	q := proof{Authority: s.Authority, Plane: s.Plane, Protocol: 1, Request: s.Request, Device: s.Device, Nonce: hex.EncodeToString(raw), Public: public(key), Issued: now.Unix(), Next: next}
	k, e := private(key)
	if e != nil {
		return q, e
	}
	message := strings.Join([]string{"hypermesh-machine-identity-v1", s.Tenant, s.Device, s.Request, s.Authority, s.Plane, q.Public, fmt.Sprint(q.Issued), q.Nonce, q.Next}, "\n")
	q.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte(message)))
	return q, nil
}
func (p Provider) exchange(ctx context.Context, s state, key, next, bootstrap string, bind bool, now time.Time) (tokenReply, error) {
	var out tokenReply
	q, e := signed(s, key, next, now)
	if e != nil {
		return out, e
	}
	raw, _ := json.Marshal(q)
	endpoint := s.Renewal
	if endpoint == "" {
		endpoint = s.Base + "/api/v1/aiuditor/machine/renew"
	}
	if bind {
		endpoint = s.Base + "/api/v1/hypermesh/agent/identity/bind"
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return out, fmt.Errorf("invalid machine identity endpoint")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return out, fmt.Errorf("invalid machine identity endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", s.Tenant)
	if bind {
		req.Header.Set("Authorization", "Bearer "+bootstrap)
	}
	client := http.Client{Timeout: 15 * time.Second}
	if p.HTTP != nil {
		client = *p.HTTP
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := client.Do(req)
	if e != nil {
		return out, fmt.Errorf("machine identity service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == 401 {
		return out, errUnauthorized
	}
	if response.StatusCode != 200 {
		return out, fmt.Errorf("machine identity service returned HTTP %d", response.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&out); e != nil {
		return out, fmt.Errorf("invalid machine token response")
	}
	expected := q.Public
	if next != "" {
		expected = next
	}
	if out.Public != expected || out.Type != "Bearer" || out.TTL < 60 || out.TTL > 600 || out.Created <= 0 || out.Created > now.Unix()+60 || !strings.HasPrefix(out.Token, "hm_msi_"+s.Device+".") || len(out.Token) != 7+36+1+43 {
		return tokenReply{}, fmt.Errorf("machine token response binding mismatch")
	}
	return out, nil
}

func identityBase(base string) (string, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("machine identity requires HTTPS")
	}
	return strings.TrimRight(base, "/"), nil
}

func (p Provider) discover(ctx context.Context, base, tenant string) (string, string, string, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/hypermesh/agent/identity/configuration?authority_id="+url.QueryEscape(p.Authority), nil)
	if e != nil {
		return "", "", "", e
	}
	req.Header.Set("X-Tenant-ID", tenant)
	// Same bound as the exchange: at most 15 seconds, shorter if injected.
	client := &http.Client{Timeout: 15 * time.Second}
	if p.HTTP != nil {
		clone := *p.HTTP
		client = &clone
		if client.Timeout <= 0 || client.Timeout > 15*time.Second {
			client.Timeout = 15 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return "", "", "", fmt.Errorf("machine authority discovery unavailable")
	}
	defer resp.Body.Close()
	var result struct {
		Authority string `json:"authority_id"`
		Plane     string `json:"control_plane_id"`
		Renewal   string `json:"renewal_url"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) != nil || !validAuthority(result.Authority) || !validAuthority(result.Plane) {
		return "", "", "", fmt.Errorf("invalid machine authority configuration")
	}
	renewal := result.Renewal
	if renewal == "" {
		renewal = "/api/v1/aiuditor/machine/renew"
	}
	if strings.HasPrefix(renewal, "/") && !strings.HasPrefix(renewal, "//") {
		renewal = base + renewal
	}
	u, e := url.Parse(renewal)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", fmt.Errorf("invalid credential-service renewal endpoint")
	}
	return result.Authority, result.Plane, renewal, nil
}
func validAuthority(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return false
		}
	}
	return true
}

func (p Provider) renew(ctx context.Context, s state, base, tenant, device, request, bootstrap string, checkpoint func(state) error) (string, error) {
	var e error
	if (p.Authority != "" && s.Authority != p.Authority) || s.Authority == "" || s.Plane == "" || s.Schema != 1 || s.Base != base || s.Tenant != tenant || s.Device != device || s.Request == "" || (request != "" && s.Request != request) {
		return "", fmt.Errorf("saved machine identity belongs to another host or network")
	}
	if _, e = private(s.Key); e != nil {
		return "", e
	}
	if s.Pending != "" {
		if _, e = private(s.Pending); e != nil {
			return "", e
		}
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	if s.Bound && s.Token != "" && s.Expires > now.Unix()+120 {
		return s.Token, nil
	}
	if s.Bound && s.Pending == "" && now.Unix()-s.Created >= 30*86400 {
		s.Pending, e = newKey()
		if e != nil {
			return "", e
		}
		if e = checkpoint(s); e != nil {
			return "", e
		}
	}
	var reply tokenReply
	if s.Pending != "" {
		// Recover even after the overlap expired if the plane committed the new key.
		reply, e = p.exchange(ctx, s, s.Pending, "", "", false, now)
		if errors.Is(e, errUnauthorized) {
			reply, e = p.exchange(ctx, s, s.Key, public(s.Pending), "", false, now)
		}
	} else {
		reply, e = p.exchange(ctx, s, s.Key, "", bootstrap, !s.Bound, now)
	}
	if e != nil {
		return "", e
	}
	if s.Pending != "" {
		s.Key = s.Pending
		s.Pending = ""
	}
	s.Bound = true
	s.Created = reply.Created
	s.Token = reply.Token
	s.Expires = now.Unix() + reply.TTL - 30
	if e = checkpoint(s); e != nil {
		return "", e
	}
	return s.Token, nil
}
