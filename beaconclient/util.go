package beaconclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var ErrHTTPErrorResponse = errors.New("got an HTTP error response")

func fetchBeacon(method, url string, payload, dst any) (code int, err error) {
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
	}

	if err != nil {
		return 0, fmt.Errorf("invalid request for %s: %w", url, err)
	}
	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
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
