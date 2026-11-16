package trustedmeter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Server struct {
	http        *http.Server
	channels    *Channels
	binding     Binding
	key         ed25519.PrivateKey
	owner       ed25519.PublicKey
	clock       ProtectedClock
	drift       int64
	files       EngineFiles
	stateDir    string
	certificate tls.Certificate
	quote       func(Attestation) ([]byte, error)
	execution   sync.Mutex
}

func guestCertificate(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Unix(0, 0), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
func NewGuestServer(g *Guest, owner ed25519.PublicKey, source EngineFiles, stateDir string, drift int64) (*Server, error) {
	if g == nil || g.clock == nil {
		return nil, ErrInvalid
	}
	return newGuestServer(g.binding, g.key, owner, g.clock, g.Quote, source, stateDir, drift)
}
func newGuestServer(b Binding, key ed25519.PrivateKey, owner ed25519.PublicKey, clock ProtectedClock, quote func(Attestation) ([]byte, error), source EngineFiles, stateDir string, drift int64) (*Server, error) {
	if len(key) != 64 || quote == nil {
		return nil, ErrInvalid
	}
	channels, err := NewChannels(b, key.Public().(ed25519.PublicKey), owner, clock, drift)
	if err != nil {
		return nil, err
	}
	files, err := SealedFiles(source, b)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			files.Close()
		}
	}()
	if err = os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	certificate, err := guestCertificate(key)
	if err != nil {
		return nil, err
	}
	server := &Server{channels: channels, binding: b, key: key, owner: owner, clock: clock, drift: drift, files: files, stateDir: stateDir, certificate: certificate, quote: quote}
	server.http = &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4096, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}}
	failed = false
	return server, nil
}
func (s *Server) Serve(listener net.Listener) error {
	return s.http.Serve(tls.NewListener(listener, s.http.TLSConfig))
}
func (s *Server) Close() error                 { err := s.http.Close(); s.files.Close(); return err }
func refuse(w http.ResponseWriter, status int) { http.Error(w, "meter request refused", status) }
func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}
func readBody(r *http.Request, limit int) ([]byte, error) {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.TLS == nil {
		refuse(w, 403)
		return
	}
	peer, err := tlsPeerKey(*r.TLS)
	if err != nil {
		refuse(w, 403)
		return
	}
	switch r.URL.Path {
	case "/history/channels/challenge":
		raw, err := readBody(r, 1024)
		var scope HistoryScope
		if err != nil || strict(raw, &scope) != nil {
			refuse(w, 400)
			return
		}
		request, err := s.channels.HistoryChallenge(peer, scope)
		if err != nil {
			refuse(w, 409)
			return
		}
		reply(w, request)
		return
	case "/channels/challenge":
		raw, err := readBody(r, 2)
		if err != nil || (len(raw) != 0 && string(raw) != "{}") {
			refuse(w, 400)
			return
		}
		request, err := s.channels.Challenge(peer)
		if err != nil {
			refuse(w, 409)
			return
		}
		reply(w, request)
		return
	case "/channels/authorize", "/history/channels/authorize":
		raw, err := readBody(r, 16384)
		if err != nil {
			refuse(w, 400)
			return
		}
		var request struct {
			Nonce string `json:"nonce"`
			Proof Signed `json:"proof"`
		}
		if strict(raw, &request) != nil {
			refuse(w, 400)
			return
		}
		var token string
		if r.URL.Path == "/history/channels/authorize" {
			token, err = s.channels.HistoryAuthorize(peer, request.Nonce, request.Proof)
		} else {
			token, err = s.channels.Authorize(peer, request.Nonce, request.Proof)
		}
		if err != nil {
			refuse(w, 403)
			return
		}
		reply(w, map[string]string{"channel": token})
		return
	}
	if r.URL.Path != "/status" && r.URL.Path != "/retire" && s.channels.Check(peer, r.Header.Get("X-Hypermesh-Meter-Channel")) != nil {
		refuse(w, 403)
		return
	}
	switch r.URL.Path {
	case "/quote":
		raw, err := readBody(r, 16384)
		if err != nil {
			refuse(w, 400)
			return
		}
		var statement Attestation
		if strict(raw, &statement) != nil {
			refuse(w, 400)
			return
		}
		report, err := s.quote(statement)
		if err != nil {
			refuse(w, 409)
			return
		}
		if s.channels.Check(peer, r.Header.Get("X-Hypermesh-Meter-Channel")) != nil {
			refuse(w, 403)
			return
		}
		reply(w, map[string]string{"report": hex.EncodeToString(report), "runtime_key": hex.EncodeToString(s.key.Public().(ed25519.PublicKey))})
	case "/status":
		raw, err := readBody(r, 1024)
		if err != nil {
			refuse(w, 400)
			return
		}
		var request struct {
			BatchID    string `json:"batch_id"`
			RuntimeKey string `json:"runtime_key"`
		}
		if strict(raw, &request) != nil || !uuidPattern.MatchString(request.BatchID) || !digestPattern.MatchString(request.RuntimeKey) {
			refuse(w, 400)
			return
		}
		if s.checkHistoryAccess(r, peer, "status", request.BatchID, request.RuntimeKey) != nil {
			refuse(w, 403)
			return
		}
		key, _ := hex.DecodeString(request.RuntimeKey)
		// Each request has its own bounded file. Historical public keys still
		// require verification against Plane's original session and count anchor.
		journal, err := s.requestJournal(key, request.BatchID)
		if err != nil {
			refuse(w, 409)
			return
		}
		entry, err := journal.Status(s.binding, request.BatchID)
		if err != nil {
			refuse(w, 409)
			return
		}
		if s.checkHistoryAccess(r, peer, "status", request.BatchID, request.RuntimeKey) != nil {
			refuse(w, 403)
			return
		}
		reply(w, entry)
	case "/retire":
		s.retire(w, r)
	case "/execute":
		s.execute(w, r, peer)
	default:
		refuse(w, 404)
	}
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type executionRequest struct {
	BatchID       string    `json:"batch_id"`
	Epoch         string    `json:"epoch"`
	MaxBillable   int64     `json:"max_billable"`
	MaxRecordOnly int64     `json:"max_record_only"`
	RelayURL      string    `json:"relay_url"`
	Messages      []message `json:"messages"`
	MaxTokens     int       `json:"max_tokens"`
}

// uniquePayload checks duplicate JSON fields while permitting Unicode prompt text.
func uniquePayload(d *json.Decoder, depth int) error {
	if depth > 12 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return ErrInvalid
			}
			keys[name] = true
			if err = uniquePayload(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if err = uniquePayload(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil || token != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func decodeExecution(raw []byte) (executionRequest, error) {
	var request executionRequest
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if err := uniquePayload(check, 0); err != nil {
		return request, err
	}
	if _, err := check.Token(); err != io.EOF {
		return request, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if !uuidPattern.MatchString(request.BatchID) || !uuidPattern.MatchString(request.Epoch) || request.MaxBillable < 0 || request.MaxRecordOnly < 0 || request.MaxTokens < 1 || request.MaxTokens > 128 || len(request.Messages) < 1 || len(request.Messages) > 64 {
		return request, ErrInvalid
	}
	for _, m := range request.Messages {
		if m.Role != "user" && m.Role != "assistant" && m.Role != "system" {
			return request, ErrInvalid
		}
	}
	return request, nil
}
func (s *Server) execute(w http.ResponseWriter, r *http.Request, peer ed25519.PublicKey) {
	if !s.execution.TryLock() {
		refuse(w, 409)
		return
	}
	defer s.execution.Unlock()
	raw, err := readBody(r, 65536)
	if err != nil {
		refuse(w, 400)
		return
	}
	request, err := decodeExecution(raw)
	if err != nil {
		refuse(w, 400)
		return
	}
	relay, err := NewRelay(request.RelayURL, s.binding, s.certificate, peer)
	if err != nil {
		refuse(w, 400)
		return
	}
	defer relay.Close()
	journal, err := s.requestJournal(s.key.Public().(ed25519.PublicKey), request.BatchID)
	if err != nil {
		refuse(w, 409)
		return
	}
	controller, err := NewController(s.binding, request.Epoch, request.BatchID, s.key, s.owner, startChannelOwner{relay, s.channels, peer, r.Header.Get("X-Hypermesh-Meter-Channel")}, s.clock, journal, s.drift, request.MaxBillable, request.MaxRecordOnly)
	if err != nil {
		refuse(w, 409)
		return
	}
	// Recheck the key-bound channel after reading the body, before any new work.
	if s.channels.Check(peer, r.Header.Get("X-Hypermesh-Meter-Channel")) != nil {
		refuse(w, 403)
		return
	}
	payload, _ := json.Marshal(struct {
		Messages  []message `json:"messages"`
		MaxTokens int       `json:"max_tokens"`
	}{request.Messages, request.MaxTokens})
	var output bytes.Buffer
	if err = RunCPU(r.Context(), controller, s.files, payload, &output); err != nil {
		refuse(w, 409)
		return
	}
	reply(w, map[string]string{"outcome": "completed", "output_hex": hex.EncodeToString(output.Bytes())})
}

// A slow model load must not turn an expired API channel into a new start.
// Active work thereafter remains bounded by independent owner execution grants.
type startChannelOwner struct {
	Owner
	channels *Channels
	peer     ed25519.PublicKey
	token    string
}

func (o startChannelOwner) Exchange(ctx context.Context, operation string, request Signed) (Signed, error) {
	if operation == "start" {
		if err := o.channels.Check(o.peer, o.token); err != nil {
			return Signed{}, err
		}
	}
	response, err := o.Owner.Exchange(ctx, operation, request)
	if err != nil {
		return Signed{}, err
	}
	if operation == "start" {
		if err = o.channels.Check(o.peer, o.token); err != nil {
			return Signed{}, err
		}
	}
	return response, nil
}

// Partitioning bounds each request without imposing a lifetime request quota.
// Reopening a partition is read-only, including a duplicate execution attempt.
func (s *Server) requestJournal(key ed25519.PublicKey, batchID string) (*Journal, error) {
	if len(key) != ed25519.PublicKeySize || !uuidPattern.MatchString(batchID) {
		return nil, ErrInvalid
	}
	path := filepath.Join(s.stateDir, hex.EncodeToString(key)+"-"+batchID+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err = reserveRequestJournal(s.stateDir); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return OpenJournal(path, s.binding, key)
}

func (s *Server) checkHistoryAccess(r *http.Request, peer ed25519.PublicKey, operation, batch, runtime string) error {
	token := r.Header.Get("X-Hypermesh-Meter-Channel")
	if s.channels.Check(peer, token) == nil {
		return nil
	}
	return s.channels.CheckHistory(peer, token, operation, batch, runtime)
}
