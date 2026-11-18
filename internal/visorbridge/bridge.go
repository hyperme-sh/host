// Package visorbridge exposes narrowly scoped machine review, never private keys
// or arbitrary command execution, to one configured local Visor account.
package visorbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sync"
	"time"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
)

var refused = errors.New("host capability bridge refused")

type Binding struct {
	Scope    string `json:"scope"`
	Owner    string `json:"owner"`
	ID       string `json:"capability_id"`
	Revision string `json:"revision"`
	Source   string `json:"source_sha256"`
	Graph    string `json:"graph_sha256"`
}

type Call struct {
	Binding
	CallID    string `json:"call_id"`
	Arguments string `json:"arguments_json"`
}

type Config struct {
	ServiceControl       *UserServiceConfig `json:"service_control,omitempty"`
	FeedbackOnly         bool               `json:"feedback_only,omitempty"`
	FeedbackGrants       bool               `json:"feedback_grants,omitempty"`
	CrashRegistrationURL string             `json:"crash_registration_url,omitempty"`
	Schema               int                `json:"schema"`
	ClientUID            uint32             `json:"client_uid"`
	Socket               string             `json:"socket"`
	Conductor            string             `json:"conductor"`
	AuthorityURL         string             `json:"authority_url"`
	DispatchConfig       string             `json:"dispatch_config"`
	Base                 string             `json:"base"`
	Tenant               string             `json:"tenant"`
	Device               string             `json:"device"`
	Identity             string             `json:"identity"`
	WireGuardKey         string             `json:"wireguard_key,omitempty"`
	Enabled              []Binding          `json:"enabled"`
	MachinePrompt        *PromptConfig      `json:"machine_prompt,omitempty"`
	PermissionPreview    *PreviewBinding    `json:"permission_preview,omitempty"`
}

type Result struct {
	Protocol   int    `json:"protocol_version"`
	CallID     string `json:"call_id"`
	CallSHA256 string `json:"call_sha256"`
	Decision   string `json:"decision"`
	Expires    int64  `json:"expires_at"`
}

type signer func(context.Context, machineidentity.CapabilityCall) ([]byte, error)
type reviewer func(context.Context, []byte) ([]byte, error)

type Bridge struct {
	config        Config
	credential    func(context.Context) (string, error)
	sign          signer
	review        reviewer
	now           func() time.Time
	busy          chan struct{}
	dispatchSlots chan struct{}
	command       func(context.Context, string, []byte, int) ([]byte, error)
}

func New(config Config) (*Bridge, error) {
	if config.FeedbackOnly {
		return newFeedbackBridge(config)
	}
	target, err := url.Parse(config.AuthorityURL)
	if err != nil || config.Schema != 1 || config.ClientUID == 0 || len(config.Enabled) > 64 || target.Scheme != "https" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Path != "/api/v1/aiuditor/capabilities/review" {
		return nil, refused
	}
	if trustedExecutable(config.Conductor) != nil || trustedConfiguration(config.DispatchConfig) != nil {
		return nil, refused
	}
	seen := map[Binding]bool{}
	for _, binding := range config.Enabled {
		if binding.Scope == "" || binding.Owner == "" || binding.ID == "" || binding.Revision == "" || len(binding.Source) != 64 || len(binding.Graph) != 64 || seen[binding] {
			return nil, refused
		}
		seen[binding] = true
	}
	config.Enabled = append([]Binding(nil), config.Enabled...)
	provider := machineidentity.Provider{Path: config.Identity}
	b := &Bridge{config: config, now: time.Now, busy: make(chan struct{}, 8), dispatchSlots: make(chan struct{}, 4)}
	b.credential = func(ctx context.Context) (string, error) {
		return provider.ExistingToken(ctx, config.Base, config.Tenant, config.Device, "")
	}
	b.sign = func(ctx context.Context, call machineidentity.CapabilityCall) ([]byte, error) {
		return provider.SignCapability(ctx, config.Base, config.Tenant, config.Device, config.WireGuardKey, call)
	}
	b.command = func(ctx context.Context, action string, raw []byte, limit int) ([]byte, error) {
		if trustedExecutable(config.Conductor) != nil || trustedConfiguration(config.DispatchConfig) != nil {
			return nil, refused
		}
		args := []string{action, "--config", config.DispatchConfig}
		if action == "machine-context" {
			args = []string{action, "--plane", config.Base}
		}
		if action == "coding-run" {
			if config.MachinePrompt == nil || !config.MachinePrompt.valid() {
				return nil, refused
			}
			args = []string{action, "--plane", config.Base, "--socket", config.MachinePrompt.Socket}
		}
		if action == "machine-prompt" || action == "continue-plan" {
			if config.MachinePrompt == nil || !config.MachinePrompt.valid() {
				return nil, refused
			}
			args = []string{action, "--socket", config.MachinePrompt.Socket}
		}
		if action == "permission-dream" || action == "permission-preview" || (action == "permission-read-review" || action == "permission-read-admit") || (action == "permission-action-review" || action == "permission-action-admit") {
			endpoint, _ := url.Parse(config.AuthorityURL)
			endpoint.Path = "/api/v1/aiuditor/access/preview"
			if action == "permission-dream" {
				endpoint.Path = "/api/v1/aiuditor/access/dream"
			}
			if action == "permission-read-review" || action == "permission-read-admit" {
				endpoint.Path = "/api/v1/aiuditor/access/read-review"
			}
			if action == "permission-action-review" || action == "permission-action-admit" {
				endpoint.Path = "/api/v1/aiuditor/access/action-review"
			}
			args = []string{action, "--plane", config.Base, "--authority", endpoint.String()}
			if action == "permission-action-admit" {
				args = append(args, "--config", config.DispatchConfig)
			}
		}
		if action == "capability-review" {
			args = []string{action, "--endpoint", config.AuthorityURL}
		}
		cmd := exec.CommandContext(ctx, config.Conductor, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
		cmd.Stdin = bytes.NewReader(raw)
		output := &boundedOutput{limit: limit}
		cmd.Stdout = output
		cmd.Stderr = io.Discard
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil || output.failed {
			return nil, refused
		}
		return output.buf.Bytes(), nil
	}
	b.review = func(ctx context.Context, raw []byte) ([]byte, error) {
		return b.command(ctx, "capability-review", raw, 4096)
	}

	return b, nil
}

type boundedOutput struct {
	buf    bytes.Buffer
	limit  int
	failed bool
	mu     sync.Mutex
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(raw) > b.limit-b.buf.Len() {
		b.failed = true
		return 0, refused
	}
	return b.buf.Write(raw)
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return refused
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return refused
	}
	return nil
}

func (b *Bridge) Review(ctx context.Context, raw []byte) (Result, error) {
	if len(raw) > (6*65536 + 4096) {
		return Result{}, refused
	}
	var call Call
	if decode(raw, &call) != nil || len(call.Arguments) > 65536 {
		return Result{}, refused
	}
	allowed := false
	for _, binding := range b.config.Enabled {
		if binding == call.Binding {
			allowed = true
			break
		}
	}
	if !allowed {
		return Result{}, refused
	}
	select {
	case b.busy <- struct{}{}:
		defer func() { <-b.busy }()
	default:
		return Result{}, refused
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	signed, err := b.sign(ctx, machineidentity.CapabilityCall{Scope: call.Scope, Owner: call.Owner, ID: call.ID, Revision: call.Revision, SourceSHA256: call.Source, GraphSHA256: call.Graph, CallID: call.CallID, Arguments: json.RawMessage(call.Arguments)})
	if err != nil {
		return Result{}, refused
	}
	// Check the response against the actual machine proof, not a caller's claim.
	var proof map[string]json.RawMessage
	if json.Unmarshal(signed, &proof) != nil {
		return Result{}, refused
	}
	delete(proof, "signature")
	canonical, err := json.Marshal(proof)
	if err != nil {
		return Result{}, refused
	}
	sum := sha256.Sum256(append([]byte("hypermesh-capability-review-v1\n"), canonical...))
	var expires int64
	if json.Unmarshal(proof["expires_at"], &expires) != nil {
		return Result{}, refused
	}
	result, err := b.review(ctx, signed)
	if err != nil {
		return Result{}, refused
	}
	var verdict struct {
		Protocol int    `json:"protocol_version"`
		CallID   string `json:"call_id"`
		Hash     string `json:"request_sha256"`
		Decision string `json:"decision"`
		Expires  int64  `json:"expires_at"`
	}
	if decode(result, &verdict) != nil || verdict.Protocol != 1 || verdict.CallID != call.CallID || verdict.Hash != hex.EncodeToString(sum[:]) || verdict.Decision != "allow" || verdict.Expires != expires || expires <= b.now().Unix() || expires > b.now().Unix()+30 {
		return Result{}, refused
	}
	bodyHash := sha256.Sum256(raw)
	return Result{1, call.CallID, hex.EncodeToString(bodyHash[:]), "allow", expires}, nil
}

func (b *Bridge) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || (uid != b.config.ClientUID && uid != 0) {
			http.Error(w, "host capability bridge refused", 403)
			return
		}
		if b.config.FeedbackOnly {
			if uid != b.config.ClientUID || uid == 0 || r.Method != "POST" || r.URL.Path != "/feedback-grant" {
				http.NotFound(w, r)
				return
			}
			b.feedback(w, r)
			return
		}
		// Only the trusted root Conductor child may obtain a machine review. The
		// non-root client cannot take an allow result to an unguarded controller.
		if uid == 0 {
			if r.Method == "GET" && r.URL.Path == "/capabilities" {
				json.NewEncoder(w).Encode(struct {
					Schema  int       `json:"schema"`
					Enabled []Binding `json:"enabled"`
				}{1, b.config.Enabled})
				return
			}
			if r.Method != "POST" || r.URL.Path != "/review" {
				http.NotFound(w, r)
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, (6*65536 + 4096)))
			if err != nil {
				http.Error(w, "host capability bridge refused", 413)
				return
			}
			result, err := b.Review(r.Context(), raw)
			if err != nil {
				http.Error(w, "host capability bridge refused", 403)
				return
			}
			json.NewEncoder(w).Encode(result)
			return
		}
		if r.URL.Path == "/feedback-grant" && r.Method == "POST" {
			b.feedback(w, r)
			return
		}
		if r.URL.Path == "/crash-register" && r.Method == "POST" {
			b.crashRegister(w, r)
			return
		}
		if r.URL.Path == "/permission-service-context" && r.Method == "GET" {
			value, err := b.serviceContext()
			if err != nil {
				http.Error(w, "Service control unavailable", 503)
				return
			}
			json.NewEncoder(w).Encode(value)
			return
		}
		if r.URL.Path == "/permission-context" && r.Method == "GET" {
			if b.config.PermissionPreview == nil || !b.config.PermissionPreview.valid() {
				http.Error(w, "Permission preview unavailable", 503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"version": 1, "configured_only": true, "tenant_id": b.config.Tenant, "device_id": b.config.Device, "binding": b.config.PermissionPreview})
			return
		}
		if (r.URL.Path == "/machine-context" && r.Method == "GET") || (r.URL.Path == "/machine-prompt" && r.Method == "POST") {
			b.machine(w, r)
			return
		}
		if r.URL.Path == "/continue-plan" && r.Method == "POST" {
			b.continuePlan(w, r)
			return
		}
		if r.URL.Path == "/coding-run" && r.Method == "POST" {
			b.coding(w, r)
			return
		}
		if r.URL.Path == "/permission-dream" && r.Method == "POST" {
			b.permissionDream(w, r)
			return
		}
		if ((r.URL.Path == "/permission-read-review" || r.URL.Path == "/permission-read-admit") || r.URL.Path == "/permission-action-review" || r.URL.Path == "/permission-action-admit" || r.URL.Path == "/permission-service-execute") && r.Method == "POST" {
			b.accessReview(w, r, true)
			return
		}
		if r.URL.Path == "/permission-preview" && r.Method == "POST" {
			b.preview(w, r)
			return
		}
		action := ""
		var raw []byte
		var err error
		switch {
		case r.Method == "GET" && r.URL.Path == "/catalog":
			action = "capability-catalog"
		case r.Method == "POST" && r.URL.Path == "/dispatch":
			action = "capability-dispatch"
			raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, (6*65536 + 4096)))
			var call Call
			if err != nil || decode(raw, &call) != nil || len(call.Arguments) > 65536 {
				http.Error(w, "host capability bridge refused", 403)
				return
			}
			enabled := false
			for _, binding := range b.config.Enabled {
				if binding == call.Binding {
					enabled = true
					break
				}
			}
			if !enabled {
				http.Error(w, "host capability bridge refused", 403)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		select {
		case b.dispatchSlots <- struct{}{}:
			defer func() { <-b.dispatchSlots }()
		default:
			http.Error(w, "host capability bridge refused", 429)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		output, err := b.command(ctx, action, raw, 6*1048576+4096)
		if err != nil || !json.Valid(output) {
			http.Error(w, "host capability bridge refused", 403)
			return
		}
		w.Write(output)
	})
}

type peerKey struct{}
