package visorbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
	result, err := b.registerCrash(r.Context(), claim)
	if err != nil {
		fail()
		return
	}
	w.Write(result)
}

func (b *Bridge) registerCrash(parent context.Context, claim crashClaim) ([]byte, error) {
	endpoint, err := url.Parse(b.config.CrashRegistrationURL)
	if err != nil {
		return nil, refused
	}
	captured, err := time.Parse(time.RFC3339, claim.Captured)
	now := b.now()
	if err != nil || len(claim.Captured) > 40 || claim.Captured[len(claim.Captured)-1:] != "Z" || captured.After(now) || now.Sub(captured) >= 24*time.Hour {
		return nil, refused
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	token, err := b.credential(ctx)
	if err != nil {
		return nil, refused
	}
	plane, err := url.Parse(b.config.Base)
	if err != nil || plane.Scheme != "https" || plane.Host == "" || plane.User != nil || plane.RawQuery != "" || plane.Fragment != "" || (plane.Path != "" && plane.Path != "/") {
		return nil, refused
	}
	plane.Path = "/api/v1/hypermesh/agent/crashes/grant"
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, refused
	}
	nonce[6] = (nonce[6] & 15) | 64
	nonce[8] = (nonce[8] & 63) | 128
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	grantBody, _ := json.Marshal(map[string]any{"version": 1, "device_id": b.config.Device, "request_id": requestID, "event_id": claim.Event, "captured_at": claim.Captured, "payload_sha256": claim.Hash})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	grantRequest, err := http.NewRequestWithContext(ctx, "POST", plane.String(), bytes.NewReader(grantBody))
	if err != nil {
		return nil, refused
	}
	grantRequest.Header.Set("Authorization", "Bearer "+token)
	grantRequest.Header.Set("X-Tenant-ID", b.config.Tenant)
	grantRequest.Header.Set("Content-Type", "application/json")
	grantResponse, err := client.Do(grantRequest)
	if err != nil {
		return nil, refused
	}
	grantRaw, err := io.ReadAll(io.LimitReader(grantResponse.Body, 4097))
	grantResponse.Body.Close()
	var grant struct {
		Version int    `json:"version"`
		Grant   string `json:"grant"`
	}
	if err != nil || grantResponse.StatusCode != 200 || len(grantRaw) > 4096 || decode(grantRaw, &grant) != nil || grant.Version != 1 || !strings.HasPrefix(grant.Grant, "hm_crash_") || len(grant.Grant) > 4096 {
		return nil, refused
	}
	body, _ := json.Marshal(map[string]any{"version": 1, "tenant": b.config.Tenant, "device": b.config.Device, "event_id": claim.Event, "captured_at": claim.Captured, "payload_sha256": claim.Hash})
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, refused
	}
	request.Header.Set("Authorization", "Bearer "+grant.Grant)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, refused
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || response.StatusCode != 200 || len(result) > 4096 {
		return nil, refused
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
		return nil, refused
	}
	return result, nil
}

// NewCrashHandler exposes only registration. The transport must authenticate the
// local caller before invoking it; no dispatcher or general signing route exists.
func NewCrashHandler(base, tenant, device, endpoint string, credential func(context.Context) (string, error)) (http.Handler, error) {
	plane, err := url.Parse(base)
	broker, be := url.Parse(endpoint)
	uuid := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	if err != nil || be != nil || credential == nil || !uuid.MatchString(tenant) || !uuid.MatchString(device) ||
		plane.Scheme != "https" || plane.Host == "" || plane.User != nil || plane.RawQuery != "" || plane.Fragment != "" || (plane.Path != "" && plane.Path != "/") ||
		broker.Scheme != "https" || broker.Host == "" || broker.User != nil || broker.RawQuery != "" || broker.Fragment != "" || broker.Path != "/api/crash/register" {
		return nil, refused
	}
	b := &Bridge{config: Config{Base: base, Tenant: tenant, Device: device, CrashRegistrationURL: endpoint}, credential: credential, now: time.Now, busy: make(chan struct{}, 8)}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/crash-register" || r.URL.RawQuery != "" {
			http.Error(w, "Unavailable", http.StatusNotFound)
			return
		}
		b.crashRegister(w, r)
	}), nil
}

// RegisterCrash uses an already-authorized in-process caller. General credentials
// are sent only to Plane; the broker receives a single-event grant.
func RegisterCrash(ctx context.Context, base, tenant, device, endpoint, event, captured, hash string, credential func(context.Context) (string, error)) ([]byte, error) {
	if _, err := NewCrashHandler(base, tenant, device, endpoint, credential); err != nil {
		return nil, err
	}
	if !crashEvent.MatchString(event) || event == "00000000000000000000000000000000" || !crashHash.MatchString(hash) {
		return nil, refused
	}
	b := &Bridge{config: Config{Base: base, Tenant: tenant, Device: device, CrashRegistrationURL: endpoint}, credential: credential, now: time.Now}
	return b.registerCrash(ctx, crashClaim{Version: 1, Event: event, Captured: captured, Hash: hash})
}
