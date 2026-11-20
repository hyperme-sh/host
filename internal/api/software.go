package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

type SoftwareCommand struct {
	RequestID      string    `json:"request_id"`
	DeviceID       string    `json:"device_id"`
	Action         string    `json:"action"`
	ExpectedSHA256 string    `json:"expected_sha256"`
	TargetSHA256   string    `json:"target_sha256"`
	ExpiresAt      time.Time `json:"expires_at"`
	Status         string    `json:"status"`
}

type SoftwareResult struct {
	DeviceID      string `json:"device_id"`
	RequestID     string `json:"request_id"`
	Outcome       string `json:"outcome"`
	RunningSHA256 string `json:"running_sha256"`
	Reason        string `json:"reason"`
}

func (c *Client) PullSoftware(ctx context.Context, device string) (*SoftwareCommand, error) {
	var out SoftwareCommand
	err := c.doJSON(ctx, http.MethodGet, "/api/v1/hypermesh/agent/software", url.Values{"device_id": {device}}, nil, http.StatusOK, &out, true)
	if err == errNoContent {
		return nil, nil
	}
	var status *StatusError
	if errors.As(err, &status) && status != nil && status.StatusCode == 404 {
		return nil, nil
	} // older Plane
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) PostSoftwareResult(ctx context.Context, result SoftwareResult) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/hypermesh/agent/software/result", nil, result, http.StatusOK, nil, true)
}
