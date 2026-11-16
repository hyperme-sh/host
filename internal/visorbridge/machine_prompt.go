package visorbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"time"
)

// PromptConfig is root-managed routing for one currently assigned local project.
type PromptConfig struct {
	PreviewBinding
	Workspace   string `json:"workspace"`
	Socket      string `json:"socket"`
	Class       string `json:"class"`
	Destination string `json:"destination"`
	MaxOutput   int    `json:"max_output_tokens"`
}

func (p PromptConfig) valid() bool {
	return p.PreviewBinding.valid() && filepath.IsAbs(p.Workspace) && filepath.Clean(p.Workspace) == p.Workspace && filepath.IsAbs(p.Socket) && len(p.Class) > 0 && len(p.Class) <= 128 && len(p.Destination) > 0 && len(p.Destination) <= 256 && p.MaxOutput > 0 && p.MaxOutput <= 32768
}
func (b *Bridge) machineBinding() map[string]any {
	p := b.config.MachinePrompt
	return map[string]any{"version": 1, "tenant_id": b.config.Tenant, "device_id": b.config.Device, "bot_id": p.Bot, "assignment_id": p.Assignment, "session_id": p.Session}
}
func (b *Bridge) machineContext(ctx context.Context) (map[string]any, error) {
	p := b.config.MachinePrompt
	if p == nil || !p.valid() || b.credential == nil {
		return nil, refused
	}
	token, e := b.credential(ctx)
	if e != nil {
		return nil, refused
	}
	raw, _ := json.Marshal(map[string]any{"credential": token, "binding": b.machineBinding()})
	result, e := b.command(ctx, "machine-context", raw, 8192)
	if e != nil {
		return nil, refused
	}
	var fact map[string]any
	if json.Unmarshal(result, &fact) != nil {
		return nil, refused
	}
	for key, value := range b.machineBinding() {
		if key == "version" {
			if fact[key] != float64(1) {
				return nil, refused
			}
		} else if fact[key] != value {
			return nil, refused
		}
	}
	expires, ok := fact["expires_at"].(float64)
	now := float64(time.Now().UnixNano()) / 1e9
	if !ok || expires <= now || expires > now+11 || fact["organization_id"] != p.Organization {
		return nil, refused
	}
	return map[string]any{"identity": fact, "plane": b.config.Base, "workspace": p.Workspace, "class": p.Class, "destination": p.Destination, "max_output_tokens": p.MaxOutput}, nil
}
func (b *Bridge) machine(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "Assigned machine prompt unavailable", 503) }
	p := b.config.MachinePrompt
	if p == nil || !p.valid() {
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
	ctx, cancel := context.WithTimeout(r.Context(), 315*time.Second)
	defer cancel()
	if r.Method == "GET" {
		fact, e := b.machineContext(ctx)
		if e != nil {
			fail()
			return
		}
		json.NewEncoder(w).Encode(fact)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 512<<10))
	if e != nil {
		fail()
		return
	}
	var input struct {
		Version     int    `json:"version"`
		Tenant      string `json:"tenant_id"`
		Device      string `json:"device_id"`
		Bot         string `json:"bot_id"`
		Assignment  string `json:"assignment_id"`
		Session     string `json:"session_id"`
		Task        string `json:"task_id"`
		Operation   string `json:"operation_id"`
		Class       string `json:"class"`
		Destination string `json:"destination"`
		Prompt      string `json:"prompt"`
		MaxOutput   int    `json:"max_output_tokens"`
	}
	if decode(raw, &input) != nil || input.Version != 1 || input.Tenant != b.config.Tenant || input.Device != b.config.Device || input.Bot != p.Bot || input.Assignment != p.Assignment || input.Session != p.Session || !nonzeroID(input.Task) || !nonzeroID(input.Operation) || input.Class != p.Class || input.Destination != p.Destination || input.MaxOutput != p.MaxOutput || len(input.Prompt) == 0 || len(input.Prompt) > 65536 {
		fail()
		return
	}
	// The owner already committed the digest of raw. Base64 preserves those bytes
	// across the child envelope, including JSON escaping and whitespace.
	token, e := b.credential(ctx)
	if e != nil {
		fail()
		return
	}
	envelope, _ := json.Marshal(map[string]any{"credential": token, "submission_base64": base64.StdEncoding.EncodeToString(raw)})
	result, e := b.command(ctx, "machine-prompt", envelope, 524288)
	if e != nil {
		fail()
		return
	}
	if !json.Valid(result) {
		fail()
		return
	}
	w.Write(result)
}
