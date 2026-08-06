package beaconclient

// Streaming alternative to GetStateValidators, used by the known-validator refresh.
//
// The response is hundreds of megabytes of JSON on mainnet, and io.ReadAll holds all
// of it in memory for as long as json.Unmarshal runs. Decoding one validator at a
// time means that body never exists.
//
// Everything the streaming path needs is in this file and nothing outside it changes,
// so the whole thing can be reverted by deleting it. StreamStateValidators is
// deliberately not on IMultiBeaconClient/IBeaconInstance - the datastore reaches it by
// type assertion, so no other implementation (including the mocks) has to know it exists.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/goccy/go-json"
)

// ErrStreamStateValidatorsUnsupported is returned when no configured beacon instance
// can stream, so the caller can fall back to GetStateValidators.
var ErrStreamStateValidatorsUnsupported = errors.New("no beacon instance supports streaming state validators")

// stateValidatorsClient bounds the whole validators request, response body included.
// http.DefaultClient has no timeout, so a beacon node that accepts the connection and
// then stops sending blocks the refresh indefinitely - and because the caller holds
// knownValidatorsIsUpdating for the duration, no later refresh can start either. The
// timeout has to stay well below the refresh interval so the next one runs cleanly.
var stateValidatorsClient = &http.Client{
	Timeout: time.Duration(cli.GetEnvInt("GETVALIDATORS_TIMEOUT_SEC", 60)) * time.Second,
}

// ValidatorCollector accumulates validators as they are decoded, so the validator set
// is never held in its serialized form.
type ValidatorCollector interface {
	// Reset discards everything collected so far. It is called once before the first
	// validator of an attempt, so a beacon node that fails part-way through leaves no
	// partial state behind for the next one.
	Reset()
	Add(index uint64, pubkey string)
}

type stateValidatorStreamer interface {
	StreamStateValidators(stateID string, collector ValidatorCollector) error
}

// StreamStateValidators streams all known validators to the collector, querying the
// beacon nodes in least-used order because it is a heavy call on the CL.
func (c *MultiBeaconClient) StreamStateValidators(stateID string, collector ValidatorCollector) error {
	supported := false
	for i, client := range c.beaconInstancesByLeastUsed() {
		streamer, ok := client.(stateValidatorStreamer)
		if !ok {
			continue
		}
		supported = true

		log := c.log.WithField("uri", client.GetURI())
		log.Debug("fetching validators")
		if err := streamer.StreamStateValidators(stateID, collector); err != nil {
			log.WithError(err).Error("failed to fetch validators")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))
		return nil
	}

	if !supported {
		return ErrStreamStateValidatorsUnsupported
	}
	return ErrBeaconNodesUnavailable
}

// StreamStateValidators loads all active and pending validators, handing each to the
// collector as it is decoded.
// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
func (c *ProdBeaconInstance) StreamStateValidators(stateID string, collector ValidatorCollector) error {
	uri := fmt.Sprintf("%s/eth/v1/beacon/states/%s/validators?status=active,pending", c.beaconURI, stateID)

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("invalid request for %s: %w", uri, err)
	}
	req.Header.Set("Accept", common.ApplicationJSON)

	resp, err := stateValidatorsClient.Do(req)
	if err != nil {
		return fmt.Errorf("client refused for %s: %w", uri, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= http.StatusMultipleChoices {
		// Bounded, because we do not want to buffer an unbounded error body either.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		return fmt.Errorf("%w: %s: %s", ErrHTTPErrorResponse, uri, body)
	}

	return decodeStateValidators(resp.Body, collector)
}

// decodeStateValidators hands every entry of the response's "data" array to the
// collector, decoding one at a time so the body is never held in full.
func decodeStateValidators(body io.Reader, collector ValidatorCollector) error {
	dec := json.NewDecoder(body)

	// Walk to the "data" array. The only other fields the beacon API puts here are
	// execution_optimistic and finalized, both booleans, so matching on the token
	// value alone cannot collide with a field value.
	for {
		token, err := dec.Token()
		if err != nil {
			return fmt.Errorf("validators response has no data field: %w", err)
		}
		if token == "data" {
			break
		}
	}
	// Check this is really the opening bracket rather than just consuming a token:
	// if "data" ever held a scalar, null, or an object, that value would be consumed
	// here, dec.More() would immediately be false, and an EMPTY validator set would be
	// returned with no error - and then installed as the authoritative map.
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("malformed validators response: %w", err)
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("validators response data is not an array, got %v", token)
	}

	// Reset only once the validators are about to arrive, so a node that fails before
	// this point leaves the collector untouched.
	collector.Reset()
	for dec.More() {
		var entry ValidatorResponseEntry
		if err := dec.Decode(&entry); err != nil {
			return fmt.Errorf("could not decode validator: %w", err)
		}
		collector.Add(entry.Index, entry.Validator.Pubkey)
	}

	// This check is load-bearing, not tidiness: dec.More() also returns false when the
	// stream ends early, so without reading the closing bracket a connection dropped
	// mid-array would look like a complete - but truncated - validator set, and get
	// installed as the authoritative one.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("truncated validators response: %w", err)
	}
	return nil
}
