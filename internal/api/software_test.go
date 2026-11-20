package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSoftwareControlUsesDeviceAuthorityAndOldPlaneFallback(t *testing.T) {
	for _, code := range []int{200, 204, 404, 403} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(HeaderTenantID) != "tenant" || r.Header.Get("Authorization") != "Bearer secret" || r.URL.Query().Get("device_id") != "device" {
					t.Error("missing device authority")
				}
				w.WriteHeader(code)
				if code == 200 {
					w.Write([]byte(`{"request_id":"request","device_id":"device","action":"update"}`))
				}
			}))
			defer server.Close()
			client := NewClient(server.URL, "tenant")
			client.DeviceSecret = "secret"
			command, err := client.PullSoftware(context.Background(), "device")
			if code == 403 {
				if err == nil {
					t.Fatal("authorization failure hidden")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (command != nil) != (code == 200) {
				t.Fatal("wrong optional command result")
			}
		})
	}
}
