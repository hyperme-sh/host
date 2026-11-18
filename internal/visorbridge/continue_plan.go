package visorbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Planning never claims a task. Binding and model route come only from config.
func (b *Bridge) continuePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "Project plan unavailable", 503) }
	p := b.config.MachinePrompt
	if p == nil || !p.valid() || b.credential == nil {
		fail()
		return
	}
	var in struct {
		Workspace string          `json:"workspace"`
		Plan      json.RawMessage `json:"plan"`
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 524288))
	if e != nil || decode(raw, &in) != nil || in.Workspace != p.Workspace || !json.Valid(in.Plan) {
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
	credential, e := b.credential(ctx)
	if e != nil {
		fail()
		return
	}
	raw, _ = json.Marshal(map[string]any{"credential": credential, "input": map[string]any{"binding": b.machineBinding(), "destination": p.Destination, "max_output_tokens": p.MaxOutput, "plan": in.Plan}})
	result, e := b.command(ctx, "continue-plan", raw, 524288)
	if e != nil || !json.Valid(result) {
		fail()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}
