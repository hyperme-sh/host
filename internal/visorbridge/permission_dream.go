package visorbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (b *Bridge) permissionDream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "Permission review unavailable", 503) }
	binding := b.config.PermissionPreview
	machine := b.config.MachinePrompt
	if binding == nil || !binding.valid() || machine == nil || !machine.valid() || machine.PreviewBinding != *binding || b.credential == nil {
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
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 131072))
	if e != nil {
		fail()
		return
	}
	var body struct {
		Version   int               `json:"version"`
		RequestID string            `json:"request_id"`
		Project   string            `json:"project"`
		Records   []json.RawMessage `json:"records"`
	}
	if decode(raw, &body) != nil || body.Version != 1 || !nonzeroID(body.RequestID) || body.Project != machine.Workspace || len(body.Records) < 1 || len(body.Records) > 8 {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, e := b.credential(ctx)
	if e != nil {
		fail()
		return
	}
	payload := map[string]any{"version": 1, "request_id": body.RequestID, "project": body.Project, "records": body.Records, "tenant_id": b.config.Tenant, "device_id": b.config.Device, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session}
	envelope, _ := json.Marshal(map[string]any{"credential": token, "dream": payload})
	result, e := b.command(ctx, "permission-dream", envelope, 131072)
	if e != nil || len(result) > 131072 {
		fail()
		return
	}
	var response struct {
		Version   int               `json:"version"`
		RequestID string            `json:"request_id"`
		Project   string            `json:"project"`
		Identity  map[string]string `json:"identity"`
	}
	if json.Unmarshal(result, &response) != nil || response.Version != 1 || response.RequestID != body.RequestID || response.Project != body.Project {
		fail()
		return
	}
	for k, v := range map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session} {
		if response.Identity[k] != v {
			fail()
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}
