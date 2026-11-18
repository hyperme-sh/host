package visorbridge

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net/http"
	"time"
)

// PreviewBinding selects an existing owner assignment, never a new authority.
// Plane checks this selection on every call; stale configuration is unavailable.
type PreviewBinding struct {
	Bot          string `json:"bot_id"`
	Assignment   string `json:"assignment_id"`
	Session      string `json:"session_id"`
	Organization string `json:"organization_id"`
}

func nonzeroID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func (p PreviewBinding) valid() bool {
	return nonzeroID(p.Bot) && nonzeroID(p.Assignment) && nonzeroID(p.Session) && nonzeroID(p.Organization)
}

type previewRequest struct {
	RequestID       string          `json:"request_id,omitempty"`
	ExpectedPolicy  string          `json:"expected_policy_revision,omitempty"`
	Project         string          `json:"project"`
	TemplateVersion int             `json:"template_version"`
	Template        json.RawMessage `json:"template"`
	Action          json.RawMessage `json:"action"`
}

func (b *Bridge) preview(w http.ResponseWriter, r *http.Request) {
	b.accessReview(w, r, false)
}
func (b *Bridge) accessReview(w http.ResponseWriter, r *http.Request, active bool) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func() { http.Error(w, "Permission preview unavailable", 503) }
	binding := b.config.PermissionPreview
	if binding == nil || !binding.valid() || !nonzeroID(b.config.Tenant) || !nonzeroID(b.config.Device) || b.credential == nil {
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
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 196608))
	if e != nil {
		fail()
		return
	}
	var body previewRequest
	if decode(raw, &body) != nil || len(body.Project) == 0 || len(body.Project) > 4096 || body.TemplateVersion != 1 || len(body.Template) == 0 || len(body.Action) == 0 {
		fail()
		return
	}
	if active {
		machine := b.config.MachinePrompt
		if machine == nil || !machine.valid() || machine.PreviewBinding != *binding || machine.Workspace != body.Project || !nonzeroID(body.RequestID) || body.ExpectedPolicy != "" && !nonzeroID(body.ExpectedPolicy) {
			fail()
			return
		}
	} else if body.RequestID != "" || body.ExpectedPolicy != "" {
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
	nonce := uuid.NewString()
	action := "permission-preview"
	if active {
		nonce = body.RequestID
		action = "permission-read-review"
		if r.URL.Path == "/permission-action-review" || r.URL.Path == "/permission-action-admit" || r.URL.Path == "/permission-service-execute" {
			action = "permission-action-review"
			if r.URL.Path != "/permission-action-review" {
				action = "permission-action-admit"
			}
		}
	}
	payload := map[string]any{"version": 1, "request_id": nonce, "tenant_id": b.config.Tenant, "device_id": b.config.Device, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session, "project": body.Project, "template_version": 1, "template": body.Template, "action": body.Action}
	if active && body.ExpectedPolicy != "" {
		payload["expected_policy_revision"] = body.ExpectedPolicy
	}
	envelope, _ := json.Marshal(map[string]any{"credential": token, "preview": payload})
	// Only the trusted Conductor child receives the short-lived credential over
	// stdin; it is never returned to the Visor account, logged or placed in argv.
	result, e := b.command(ctx, action, envelope, 16384)
	if e != nil {
		fail()
		return
	}
	var response struct {
		Version     int               `json:"version"`
		RequestID   string            `json:"request_id"`
		PreviewOnly bool              `json:"preview_only"`
		Identity    map[string]string `json:"identity"`
	}
	if len(result) > 16384 || json.Unmarshal(result, &response) != nil || response.Version != 1 || response.RequestID != nonce || response.PreviewOnly == active {
		fail()
		return
	}
	for key, value := range map[string]string{"tenant_id": b.config.Tenant, "device_id": b.config.Device, "organization_id": binding.Organization, "bot_id": binding.Bot, "assignment_id": binding.Assignment, "session_id": binding.Session} {
		if response.Identity[key] != value {
			fail()
			return
		}
	}
	if r.URL.Path == "/permission-service-execute" {
		output, err := b.restartService(ctx, body.Action, result)
		if err != nil {
			fail()
			return
		}
		w.Write(output)
		return
	}
	w.Write(result)
}
