package trustedmeter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Relay uses the Gateway key authorized by Plane, not certificate names or
// untrusted guest wall time. TLS still verifies the peer's key possession.
type Relay struct {
	client   *http.Client
	endpoint string
	binding  Binding
}

func tlsPeerKey(state tls.ConnectionState) (ed25519.PublicKey, error) {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return nil, ErrInvalid
	}
	key, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != 32 {
		return nil, ErrInvalid
	}
	return key, nil
}
func NewRelay(endpoint string, b Binding, certificate tls.Certificate, peer ed25519.PublicKey) (*Relay, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/trusted-meter/relay" || b.Validate() != nil || len(peer) != 32 {
		return nil, ErrInvalid
	}
	pinned := append(ed25519.PublicKey{}, peer...)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 4096, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		// Owner authorization supplies the exact key instead of PKI wall-time checks.
		InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			key, err := tlsPeerKey(state)
			if err != nil || !key.Equal(pinned) {
				return ErrInvalid
			}
			return nil
		},
	}}
	return &Relay{client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}, endpoint: parsed.String(), binding: b}, nil
}
func (r *Relay) Close() { r.client.CloseIdleConnections() }
func (r *Relay) Exchange(ctx context.Context, operation string, record Signed) (Signed, error) {
	if operation != "start" && operation != "renew" && operation != "checkpoint" {
		return Signed{}, ErrInvalid
	}
	payload := struct {
		Binding   Binding `json:"binding"`
		Operation string  `json:"operation"`
		Request   Signed  `json:"request"`
	}{r.binding, operation, record}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) > 16384 {
		return Signed{}, ErrInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(raw))
	if err != nil {
		return Signed{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return Signed{}, ErrDisputed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Signed{}, ErrDisputed
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil {
		return Signed{}, ErrDisputed
	}
	return DecodeSigned(raw)
}
