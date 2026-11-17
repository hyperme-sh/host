package visorbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var crashEvent = regexp.MustCompile(`^[a-f0-9]{32}$`)
var crashHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type crashClaim struct {
	Version  int    `json:"version"`
	Event    string `json:"event_id"`
	Captured string `json:"captured_at"`
	Hash     string `json:"payload_sha256"`
}

func (b *Bridge) crashRegister(w http.ResponseWriter, r *http.Request) {
	fail := func() { http.Error(w, "Crash registration unavailable", 503) }
	endpoint, err := url.Parse(b.config.CrashRegistrationURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/api/crash/register" || b.credential == nil {
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
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	var claim crashClaim
	if err != nil || decode(raw, &claim) != nil || claim.Version != 1 || !crashEvent.MatchString(claim.Event) || claim.Event == "00000000000000000000000000000000" || !crashHash.MatchString(claim.Hash) {
		fail()
		return
	}
	captured, err := time.Parse(time.RFC3339, claim.Captured)
	now := b.now()
	if err != nil || len(claim.Captured) > 40 || claim.Captured[len(claim.Captured)-1:] != "Z" || captured.After(now) || now.Sub(captured) >= 24*time.Hour {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	token, err := b.credential(ctx)
	if err != nil {
		fail()
		return
	}
	body, _ := json.Marshal(map[string]any{"version": 1, "tenant": b.config.Tenant, "device": b.config.Device, "event_id": claim.Event, "captured_at": claim.Captured, "payload_sha256": claim.Hash})
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(body))
	if err != nil {
		fail()
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
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
	result, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || response.StatusCode != 200 || len(result) > 4096 {
		fail()
		return
	}
	var fact struct {
		Version    int    `json:"version"`
		Registered bool   `json:"registered"`
		Tenant     string `json:"tenant"`
		Subject    string `json:"subject"`
		Device     string `json:"device"`
		Project    int    `json:"project"`
		Event      string `json:"event_id"`
		Captured   string `json:"captured_at"`
		Hash       string `json:"payload_sha256"`
	}
	if decode(result, &fact) != nil || fact.Version != 1 || !fact.Registered || fact.Tenant != b.config.Tenant || fact.Device != b.config.Device || fact.Subject == "" || fact.Project < 1 || fact.Event != claim.Event || fact.Captured != claim.Captured || fact.Hash != claim.Hash {
		fail()
		return
	}
	w.Write(result)
}
