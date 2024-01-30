package beaconclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrHTTPErrorResponse     = errors.New("got an HTTP error response")
	ErrInvalidRequestPayload = errors.New("invalid request payload")

	StateIDHead      = "head"
	StateIDGenesis   = "genesis"
	StateIDFinalized = "finalized"
	StateIDJustified = "justified"
)

func parseBroadcastModeString(s string) (BroadcastMode, bool) {
	broadcastModeMap := map[string]BroadcastMode{
		"gossip":                     Gossip,
		"consensus":                  Consensus,
		"consensus_and_equivocation": ConsensusAndEquivocation,
	}
	b, ok := broadcastModeMap[strings.ToLower(s)]
	return b, ok
}

func makeJSONRequest(method, url string, payload any) (*http.Request, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("could not marshal request: %w", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid request for %s: %w", url, err)
	}
	// Set content-type
	req.Header.Add("Content-Type", "application/json")
	return req, nil
}

func makeSSZRequest(method, url string, payload any) (*http.Request, error) {
	payloadBytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type for SSZ request: %w", ErrInvalidRequestPayload)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid request for %s: %w", url, err)
	}
	// Set content-type
	req.Header.Add("Content-Type", "application/octet-stream")
	return req, nil
}

func fetchBeacon(method, url string, payload, dst any, timeout *time.Duration, headers http.Header, ssz bool) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
	} else {
		if ssz {
			req, err = makeSSZRequest(method, url, payload)
		} else {
			req, err = makeJSONRequest(method, url, payload)
		}
	}

	if err != nil {
		return 0, fmt.Errorf("invalid request for %s: %w", url, err)
	}

	for k, v := range headers {
		req.Header.Add(k, v[0])
	}
	req.Header.Set("accept", "application/json")

	client := http.DefaultClient
	if timeout != nil && timeout.Seconds() > 0 {
		client = &http.Client{ //nolint:exhaustruct
			Timeout: *timeout,
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("client refused for %s: %w", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("could not read response body for %s: %w", url, err)
	}

	if resp.StatusCode >= http.StatusMultipleChoices {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal error response from beacon node for %s from %s: %w", url, string(bodyBytes), err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %s", ErrHTTPErrorResponse, ec.Message)
	}

	if dst != nil {
		err = json.Unmarshal(bodyBytes, dst)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response for %s from %s: %w", url, string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}
