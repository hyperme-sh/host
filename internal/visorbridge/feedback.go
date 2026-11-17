package visorbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var feedbackUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func feedbackID(s string) bool {
	return feedbackUUID.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func feedbackOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, refused
	}
	return u, nil
}

type feedbackGrant struct {
	Version   int    `json:"version"`
	Grant     string `json:"grant"`
	ExpiresIn int    `json:"expires_in"`
}

func (b *Bridge) feedback(w http.ResponseWriter, r *http.Request) {
	fail := func() { http.Error(w, "Feedback grant unavailable", http.StatusServiceUnavailable) }
	plane, err := feedbackOrigin(b.config.Base)
	if !b.config.FeedbackGrants || err != nil || b.credential == nil || !feedbackID(b.config.Device) || !feedbackID(b.config.Tenant) || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail()
		return
	}
	var input struct {
		Version int  `json:"version"`
		OptIn   bool `json:"human_reports_opt_in"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256))
	if err != nil || decode(raw, &input) != nil || input.Version != 1 || !input.OptIn {
		fail()
		return
	}
	select {
	case b.busy <- struct{}{}:
		defer func() { <-b.busy }()
	default:
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	token, err := b.credential(ctx)
	if err != nil || !strings.HasPrefix(token, "hm_msi_") {
		fail()
		return
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		fail()
		return
	}
	nonce[6] = (nonce[6] & 15) | 64
	nonce[8] = (nonce[8] & 63) | 128
	id := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	body, _ := json.Marshal(map[string]any{"version": 1, "device_id": b.config.Device, "request_id": id})
	plane.Path = "/api/v1/hypermesh/agent/feedback/grant"
	request, err := http.NewRequestWithContext(ctx, "POST", plane.String(), bytes.NewReader(body))
	if err != nil {
		fail()
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Tenant-ID", b.config.Tenant)
	request.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		fail()
		return
	}
	defer response.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(response.Body, 4097))
	var grant feedbackGrant
	if err != nil || len(raw) > 4096 || response.StatusCode != 200 || decode(raw, &grant) != nil || !validFeedbackGrant(grant, b.config.Tenant, b.config.Device, id, b.now()) {
		fail()
		return
	}
	json.NewEncoder(w).Encode(grant)
}

// Plane's authenticated TLS response is the authority here. These checks bind
// the response to this request; intake independently verifies the signature.
func validFeedbackGrant(g feedbackGrant, tenant, device, id string, now time.Time) bool {
	if g.Version != 1 || g.ExpiresIn != 60 || !strings.HasPrefix(g.Grant, "hm_feedback_") || len(g.Grant) > 4000 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(g.Grant, "hm_feedback_"), ".")
	if len(parts) != 3 {
		return false
	}
	header, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	var h struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	var c struct {
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		Tenant   string `json:"tenant_id"`
		Device   string `json:"device_id"`
		ID       string `json:"jti"`
		Issued   int64  `json:"iat"`
		Expires  int64  `json:"exp"`
		Use      string `json:"token_use"`
	}
	if e1 != nil || e2 != nil || e3 != nil || len(signature) != 64 || decode(header, &h) != nil || decode(payload, &c) != nil {
		return false
	}
	issuer, err := url.Parse(c.Issuer)
	return err == nil && issuer.Scheme == "https" && issuer.Host != "" && issuer.User == nil && issuer.RawQuery == "" && issuer.Fragment == "" &&
		h.Algorithm == "EdDSA" && h.Type == "JWT" && c.Audience == "hypermesh-feedback-v1" && c.Use == "native-feedback-v1" && feedbackID(c.Subject) &&
		c.Tenant == tenant && c.Device == device && c.ID == id && c.Issued <= now.Unix() && c.Issued > now.Unix()-60 && c.Expires == c.Issued+60 && c.Expires > now.Unix()
}
