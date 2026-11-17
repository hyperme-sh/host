package visorbridge

import (
	"context"
	"errors"
	"net/http/httptest"
	"runtime"
	"testing"
)

func feedbackOnlyConfig() Config {
	return Config{Schema: 1, ClientUID: 501, FeedbackOnly: true, FeedbackGrants: true,
		Socket: "/private/var/run/hypermesh/feedback.sock", Identity: "/private/var/lib/hypermesh/machine.json",
		Base: "https://plane.example.test", Tenant: feedbackTenant, Device: feedbackDevice}
}
func TestFeedbackOnlyModeIsExplicitAndIsolated(t *testing.T) {
	c := feedbackOnlyConfig()
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if b.command != nil || b.sign != nil || b.review != nil {
		t.Fatal("unrelated authority installed")
	}
	calls := 0
	b.credential = func(context.Context) (string, error) { calls++; return "", errors.New("fixture stop") }
	for _, uid := range []uint32{0, 502, 501} {
		for _, path := range []string{"/catalog", "/dispatch", "/review", "/capabilities", "/machine-prompt", "/permission-preview", "/crash-register"} {
			w := feedbackCall(b, uid, path, `{}`)
			if w.Code == 200 {
				t.Fatal("unrelated route enabled", uid, path)
			}
		}
	}
	if calls != 0 {
		t.Fatal("credentials used for unrelated route")
	}
	for _, uid := range []uint32{0, 502} {
		feedbackCall(b, uid, "/feedback-grant", `{"version":1,"human_reports_opt_in":true}`)
	}
	if calls != 0 {
		t.Fatal("wrong peer reached credential")
	}
	feedbackCall(b, 501, "/feedback-grant", `{"version":1,"human_reports_opt_in":true}`)
	if calls != 1 {
		t.Fatal("configured peer did not reach credential")
	}
	r := httptest.NewRequest("GET", "/feedback-grant", nil)
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, uint32(501)))
	b.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if calls != 1 {
		t.Fatal("wrong method reached credential")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.FeedbackGrants = false }, func(c *Config) { c.ClientUID = 0 },
		func(c *Config) { c.Schema = 0 }, func(c *Config) { c.Base = "http://plane.test" },
		func(c *Config) { c.Device = "invalid" }, func(c *Config) { c.Tenant = "invalid" },
		func(c *Config) { c.Socket = "relative" }, func(c *Config) { c.Identity = "relative" },
		func(c *Config) { c.Conductor = "/bin/tool" }, func(c *Config) { c.DispatchConfig = "/config" },
		func(c *Config) { c.AuthorityURL = "https://plane.test" }, func(c *Config) { c.CrashRegistrationURL = "https://plane.test" },
		func(c *Config) { c.WireGuardKey = "private" }, func(c *Config) { c.Enabled = []Binding{{ID: "capability"}} },
		func(c *Config) { c.MachinePrompt = &PromptConfig{} }, func(c *Config) { c.PermissionPreview = &PreviewBinding{} },
	} {
		invalid := c
		mutate(&invalid)
		if _, err := New(invalid); err == nil {
			t.Fatal("invalid feedback mode accepted")
		}
	}
	if runtime.GOOS == "darwin" {
		c.FeedbackOnly = false
		if _, err := New(c); err == nil {
			t.Fatal("general macOS bridge enabled")
		}
		if trustedExecutable("/bin/sh") == nil || controllerStateDir("/private/tmp") == nil {
			t.Fatal("unrelated platform authority enabled")
		}
	}
}
