// Package hostcrash reduces runtime failures to fixed, content-free events.
package hostcrash

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("host crash reporting unavailable")
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var keyPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Event struct {
	ID, Captured, Hash string
	Body               []byte
}

// NewEvent accepts no raw crash text. Runtime crash output only establishes that
// a fatal Go failure occurred; its contents never enter the event.
func NewEvent(tenant string, captured time.Time) (Event, error) {
	if !uuidPattern.MatchString(tenant) {
		return Event{}, ErrUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Event{}, ErrUnavailable
	}
	event := Event{ID: hex.EncodeToString(id[:]), Captured: captured.UTC().Format(time.RFC3339Nano)}
	release := buildinfo.CurrentVersion()
	if !regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,63}$`).MatchString(release) {
		release = "development"
	}
	tags := map[string]string{"tenant_id": tenant}
	if channel := buildinfo.CurrentChannel(); channel == "test" || channel == "prod" {
		tags["channel"] = channel
	}
	body, err := json.Marshal(map[string]any{
		"event_id": event.ID, "timestamp": event.Captured, "platform": "go", "level": "fatal",
		"release": "hypermesh-host@" + release, "message": "Host Go runtime terminated unexpectedly",
		"exception": map[string]any{"values": []map[string]string{{"type": "go_runtime_crash"}}},
		"tags":      tags,
	})
	if err != nil {
		return Event{}, ErrUnavailable
	}
	event.Body = body
	sum := sha256.Sum256(body)
	event.Hash = hex.EncodeToString(sum[:])
	return event, nil
}

type Destination struct {
	endpoint, key string
	project       int
}

// ParseDestination requires HTTPS and a canonical single-project DSN. The broker
// must share the ingest origin; configuration cannot redirect a registered event.
func ParseDestination(dsn, broker string) (Destination, error) {
	u, err := url.Parse(dsn)
	b, be := url.Parse(broker)
	if err != nil || be != nil || u.Scheme != "https" || u.Host == "" || u.User == nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !keyPattern.MatchString(u.User.Username()) {
		return Destination{}, ErrUnavailable
	}
	if _, set := u.User.Password(); set {
		return Destination{}, ErrUnavailable
	}
	if b.Scheme != "https" || b.Host != u.Host || b.User != nil || b.Path != "/api/crash/register" || b.RawPath != "" || b.RawQuery != "" || b.Fragment != "" {
		return Destination{}, ErrUnavailable
	}
	project, err := strconv.Atoi(strings.TrimPrefix(u.Path, "/"))
	if err != nil || project < 1 || u.Path != "/"+strconv.Itoa(project) {
		return Destination{}, ErrUnavailable
	}
	key := u.User.Username()
	u.User = nil
	u.Path = "/api/" + strconv.Itoa(project) + "/envelope/"
	return Destination{endpoint: u.String(), key: key, project: project}, nil
}

type Register func(context.Context, Event) ([]byte, error)

// Send performs exactly one registration and one upload. It never retries an
// uncertain outcome and never forwards raw material or a machine credential.
func (d Destination) Send(ctx context.Context, tenant, device string, event Event, register Register) error {
	if d.endpoint == "" || !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(device) || register == nil {
		return ErrUnavailable
	}
	sum := sha256.Sum256(event.Body)
	if hex.EncodeToString(sum[:]) != event.Hash || len(event.Body) > 2048 {
		return ErrUnavailable
	}
	raw, err := register(ctx, event)
	if err != nil || len(raw) > 4096 {
		return ErrUnavailable
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fact) != nil || decoder.Decode(new(any)) != io.EOF || fact.Version != 1 || !fact.Registered || fact.Tenant != tenant || fact.Device != device || fact.Subject == "" || fact.Project != d.project || fact.Event != event.ID || fact.Captured != event.Captured || fact.Hash != event.Hash {
		return ErrUnavailable
	}
	header, _ := json.Marshal(map[string]string{"event_id": event.ID})
	item, _ := json.Marshal(map[string]any{"type": "event", "length": len(event.Body)})
	envelope := bytes.Join([][]byte{header, item, event.Body}, []byte("\n"))
	req, err := http.NewRequestWithContext(ctx, "POST", d.endpoint, bytes.NewReader(envelope))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-sentry-envelope")
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7,sentry_key="+d.key+",sentry_client=hypermesh-host")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return ErrUnavailable
	}
	return nil
}
