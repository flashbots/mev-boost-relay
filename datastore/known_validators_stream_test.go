package datastore

import (
	"errors"
	"fmt"
	"testing"

	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

var errBeaconTest = errors.New("beacon test error")

func testValidatorEntry(index uint64) beaconclient.ValidatorResponseEntry {
	return beaconclient.ValidatorResponseEntry{
		Index: index,
		Validator: beaconclient.ValidatorResponseValidatorData{
			// The prefix is deliberately upper-case so that the normalisation
			// assertions below are not vacuous.
			Pubkey: fmt.Sprintf("0xABCDEF%090d", index),
		},
	}
}

// bufferedBeaconClient implements only the buffered path, like any beacon client
// that predates the streaming refresh.
type bufferedBeaconClient struct {
	*beaconclient.MockMultiBeaconClient
	validators []beaconclient.ValidatorResponseEntry
	err        error
	calls      int
}

func newBufferedBeaconClient(validators ...beaconclient.ValidatorResponseEntry) *bufferedBeaconClient {
	return &bufferedBeaconClient{
		MockMultiBeaconClient: beaconclient.NewMockMultiBeaconClient(),
		validators:            validators,
	}
}

func (c *bufferedBeaconClient) GetStateValidators(stateID string) (*beaconclient.GetStateValidatorsResponse, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return &beaconclient.GetStateValidatorsResponse{Data: c.validators}, nil
}

// streamingBeaconClient implements both paths, so fetchKnownValidators can choose.
type streamingBeaconClient struct {
	*bufferedBeaconClient
	streamErr   error
	streamCalls int
}

func newStreamingBeaconClient(validators ...beaconclient.ValidatorResponseEntry) *streamingBeaconClient {
	return &streamingBeaconClient{bufferedBeaconClient: newBufferedBeaconClient(validators...)}
}

func (c *streamingBeaconClient) StreamStateValidators(stateID string, collector beaconclient.ValidatorCollector) error {
	c.streamCalls++
	if c.streamErr != nil {
		return c.streamErr
	}
	collector.Reset()
	for _, v := range c.validators {
		collector.Add(v.Index, v.Validator.Pubkey)
	}
	return nil
}

// withStreamDecode sets the feature flag for the duration of a test.
func withStreamDecode(t *testing.T, enabled bool) {
	t.Helper()
	previous := ffStreamDecodeKnownValidators
	ffStreamDecodeKnownValidators = enabled
	t.Cleanup(func() { ffStreamDecodeKnownValidators = previous })
}

func TestFetchKnownValidatorsPathSelection(t *testing.T) {
	t.Run("flag off uses the buffered path even when streaming is available", func(t *testing.T) {
		withStreamDecode(t, false)

		client := newStreamingBeaconClient(testValidatorEntry(1))
		byPubkey, byIndex, err := fetchKnownValidators(common.TestLog, client)
		require.NoError(t, err)

		require.Equal(t, 1, client.calls)
		require.Equal(t, 0, client.streamCalls)
		require.Len(t, byPubkey, 1)
		require.Len(t, byIndex, 1)
	})

	t.Run("flag on uses the streaming path", func(t *testing.T) {
		withStreamDecode(t, true)

		client := newStreamingBeaconClient(testValidatorEntry(1))
		byPubkey, byIndex, err := fetchKnownValidators(common.TestLog, client)
		require.NoError(t, err)

		require.Equal(t, 1, client.streamCalls)
		require.Equal(t, 0, client.calls, "streaming succeeded, the buffered path must not also run")
		require.Len(t, byPubkey, 1)
		require.Len(t, byIndex, 1)
	})

	t.Run("flag on falls back when the client cannot stream", func(t *testing.T) {
		withStreamDecode(t, true)

		client := newBufferedBeaconClient(testValidatorEntry(1))
		_, byIndex, err := fetchKnownValidators(common.TestLog, client)
		require.NoError(t, err)

		require.Equal(t, 1, client.calls)
		require.Len(t, byIndex, 1)
	})

	t.Run("flag on falls back when no beacon node supports streaming", func(t *testing.T) {
		withStreamDecode(t, true)

		client := newStreamingBeaconClient(testValidatorEntry(1))
		client.streamErr = beaconclient.ErrStreamStateValidatorsUnsupported

		_, byIndex, err := fetchKnownValidators(common.TestLog, client)
		require.NoError(t, err)

		require.Equal(t, 1, client.streamCalls)
		require.Equal(t, 1, client.calls, "should have fallen back to the buffered path")
		require.Len(t, byIndex, 1)
	})
}

func TestFetchKnownValidatorsErrors(t *testing.T) {
	t.Run("buffered errors are returned", func(t *testing.T) {
		withStreamDecode(t, false)

		client := newBufferedBeaconClient()
		client.err = errBeaconTest

		byPubkey, byIndex, err := fetchKnownValidators(common.TestLog, client)
		require.ErrorIs(t, err, errBeaconTest)
		require.Nil(t, byPubkey)
		require.Nil(t, byIndex)
	})

	// A genuine streaming failure must not silently re-run the request through the
	// buffered path: that would double an already very heavy call on the CL.
	t.Run("streaming errors are returned without falling back", func(t *testing.T) {
		withStreamDecode(t, true)

		client := newStreamingBeaconClient(testValidatorEntry(1))
		client.streamErr = errBeaconTest

		_, _, err := fetchKnownValidators(common.TestLog, client)
		require.ErrorIs(t, err, errBeaconTest)
		require.Equal(t, 1, client.streamCalls)
		require.Equal(t, 0, client.calls, "must not retry the heavy call on the buffered path")
	})
}

// An empty validator set must never be installed: it would empty the lookup maps and
// fail proposer-pubkey lookup for every slot until the next successful refresh.
func TestFetchKnownValidatorsRejectsEmptySet(t *testing.T) {
	for name, streaming := range map[string]bool{"buffered": false, "streamed": true} {
		t.Run(name, func(t *testing.T) {
			withStreamDecode(t, streaming)

			byPubkey, byIndex, err := fetchKnownValidators(common.TestLog, newStreamingBeaconClient())
			require.ErrorIs(t, err, ErrNoKnownValidators)
			require.Nil(t, byPubkey)
			require.Nil(t, byIndex)
		})
	}
}

// TestFetchKnownValidatorsPathsAgree is what makes the flag safe to flip: both
// paths must produce byte-identical lookup maps for the same validator set.
func TestFetchKnownValidatorsPathsAgree(t *testing.T) {
	validators := make([]beaconclient.ValidatorResponseEntry, 0, 32)
	for i := range uint64(32) {
		validators = append(validators, testValidatorEntry(i))
	}

	withStreamDecode(t, false)
	bufferedByPubkey, bufferedByIndex, err := fetchKnownValidators(common.TestLog, newStreamingBeaconClient(validators...))
	require.NoError(t, err)

	withStreamDecode(t, true)
	streamedByPubkey, streamedByIndex, err := fetchKnownValidators(common.TestLog, newStreamingBeaconClient(validators...))
	require.NoError(t, err)

	require.Len(t, streamedByIndex, len(validators))
	require.Equal(t, bufferedByPubkey, streamedByPubkey)
	require.Equal(t, bufferedByIndex, streamedByIndex)

	// Both must lower-case the pubkey, or GetKnownValidatorPubkeyByIndex and
	// IsKnownValidator stop agreeing with the rest of the relay.
	for pubkey := range streamedByPubkey {
		require.Equal(t, common.NewPubkeyHex(string(pubkey)), pubkey)
	}
}

func TestKnownValidatorsCollector(t *testing.T) {
	collector := new(knownValidatorsCollector)
	collector.Reset()

	collector.Add(1, "0xAABB")
	collector.Add(2, "0xccdd")
	require.Len(t, collector.byIndex, 2)
	require.Equal(t, common.PubkeyHex("0xaabb"), collector.byIndex[1])
	require.Equal(t, uint64(1), collector.byPubkey["0xaabb"])

	// Reset must drop everything, so a retry against another beacon node cannot
	// inherit a partial validator set.
	collector.Reset()
	require.Empty(t, collector.byIndex)
	require.Empty(t, collector.byPubkey)

	collector.Add(3, "0xeeff")
	require.Len(t, collector.byIndex, 1)
}
