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
	ErrHTTPErrorResponse = errors.New("got an HTTP error response")

	StateIDHead      = "head"
	StateIDGenesis   = "genesis"
	StateIDFinalized = "finalized"
	StateIDJustified = "justified"
)

func parseBroadcastValidationString(s string) (BroadcastValidation, bool) {
	broadcastValidationMap := map[string]BroadcastValidation{
		"gossip":                     Gossip,
		"consensus":                  Consensus,
		"consensus_and_equivocation": ConsensusAndEquivocation,
	}
	b, ok := broadcastValidationMap[strings.ToLower(s)]
	return b, ok
}

func fetchBeacon(method, url string, payload, dst any, timeout *time.Duration, headers http.Header) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequest(method, url, bytes.NewReader(payloadBytes))

		// Set content-type
		req.Header.Add("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Add(k, v[0])
		}
	}

	if err != nil {
		return 0, fmt.Errorf("invalid request for %s: %w", url, err)
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
