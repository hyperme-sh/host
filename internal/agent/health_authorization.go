package agent

import (
	"context"
	"net/http"
	"time"

	"github.com/FyberLabs/hypermesh-host/terms"
)

// handleHealthAuthorization is a local owner-socket check, not a transferable
// credential. Every check revalidates enrollment through the machine client.
// It neither prompts nor changes sale state, and exports no machine secret.
func (a *Agent) handleHealthAuthorization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	st, ok := readDeviceState(a.cfg.StateDir)
	accepted, err := time.Parse(time.RFC3339, st.AcceptedAt)
	now := time.Now().UTC()
	if !ok || err != nil || accepted.After(now) || st.DeviceID == "" || st.DeviceSecret == "" || st.TermsVersion != terms.Version || st.TermsSHA256 != terms.SHA256() || a.client == nil || a.client.DeviceID != st.DeviceID || a.client.TenantID == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// This existing read-only machine route authenticates even when no tunnel is
	// assigned (204). Tunnel availability and selling posture do not grant health
	// authority; only a successful current machine-authenticated request does.
	if _, err := a.client.GetTunnel(ctx, st.DeviceID); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	current, ok := readDeviceState(a.cfg.StateDir)
	if !ok || current != st || ctx.Err() != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	encodeJSON(w, http.StatusOK, struct {
		Version      int       `json:"version"`
		Policy       string    `json:"policy"`
		DeviceID     string    `json:"device_id"`
		TenantID     string    `json:"tenant_id"`
		TermsVersion string    `json:"terms_version"`
		TermsSHA256  string    `json:"terms_sha256"`
		CheckedAt    time.Time `json:"checked_at"`
	}{1, "host-agreement", st.DeviceID, a.client.TenantID, terms.Version, terms.SHA256(), time.Now().UTC()})
}
