package visorbridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// coding uses only the root-managed target and the private caller's cancellation.
// No request-supplied destination, workspace, credential or prompt is accepted.
func (b *Bridge) coding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "Assigned coding task unavailable; no retry", 503) }
	p := b.config.MachinePrompt
	if p == nil || !p.valid() || b.credential == nil {
		fail()
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	var empty struct{}
	if e != nil || decode(raw, &empty) != nil {
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
	if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(330*time.Second)) != nil {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 325*time.Second)
	defer cancel()
	token, e := b.credential(ctx)
	if e != nil {
		fail()
		return
	}
	target := b.machineBinding()
	target["workspace"] = p.Workspace
	target["class"] = p.Class
	target["destination"] = p.Destination
	target["max_output_tokens"] = p.MaxOutput
	envelope, _ := json.Marshal(map[string]any{"credential": token, "target": target})
	result, e := b.command(ctx, "coding-run", envelope, 8192)
	if e != nil {
		fail()
		return
	}
	var output struct {
		Version int    `json:"version"`
		Task    string `json:"task_id,omitempty"`
		State   string `json:"state"`
		SHA     string `json:"output_sha256,omitempty"`
	}
	if decode(result, &output) != nil || output.Version != 1 {
		fail()
		return
	}
	if output.State == "idle" {
		if output.Task != "" || output.SHA != "" {
			fail()
			return
		}
	} else if !nonzeroID(output.Task) || (output.State != "unknown" && output.State != "output-observed") {
		fail()
		return
	}
	if output.SHA != "" {
		decoded, err := hex.DecodeString(output.SHA)
		if err != nil || len(decoded) != 32 {
			fail()
			return
		}
	}
	json.NewEncoder(w).Encode(output)
}
