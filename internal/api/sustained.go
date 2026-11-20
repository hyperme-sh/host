package api

import (
	"context"
	"encoding/json"
	"net/http"
)

type SustainedResult struct {
	DeviceID            string          `json:"device_id"`
	JobID               string          `json:"job_id"`
	EnvironmentHash     string          `json:"environment_hash"`
	MeasurementProtocol string          `json:"measurement_protocol"`
	Passed              bool            `json:"passed"`
	FileHash            string          `json:"file_hash,omitempty"`
	Measurement         json.RawMessage `json:"measurement,omitempty"`
	ThermalC            *float64        `json:"thermal_c,omitempty"`
}

func (c *Client) PostSustainedResult(ctx context.Context, result SustainedResult) error {
	return c.doJSON(ctx, http.MethodPost, Prefix+"/agent/certification/sustained-result", nil, result, http.StatusOK, nil, true)
}
