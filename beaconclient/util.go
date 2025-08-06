package beaconclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/goccy/go-json"
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

func fetchBeacon(method, url string, payload []byte, dst any, httpClient *http.Client, headers http.Header, ssz bool) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
	} else {
		req, err = http.NewRequest(method, url, bytes.NewReader(payload))
	}

	if err != nil {
		return 0, fmt.Errorf("invalid request for %s: %w", url, err)
	}

	if ssz {
		req.Header.Add("Content-Type", common.ApplicationOctetStream)
	} else {
		req.Header.Add("Content-Type", common.ApplicationJSON)
	}

	for k, v := range headers {
		req.Header.Add(k, v[0])
	}
	req.Header.Set("Accept", common.ApplicationJSON)

	client := http.DefaultClient
	if httpClient != nil {
		client = httpClient
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
