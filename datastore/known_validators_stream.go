package datastore

// Streaming known-validator refresh, kept entirely out of datastore.go so the
// whole change is this file plus one call swap in
// RefreshKnownValidatorsWithoutChecks.
//
// The getStateValidators response is hundreds of megabytes of JSON on mainnet, and
// buffering it costs roughly twice that in live heap. Building the lookup maps
// straight off the decoder avoids ever holding the serialized form.

import (
	"errors"
	"os"

	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
)

// ErrNoKnownValidators is returned when the beacon node reports an empty validator set.
// Installing that would leave the lookup maps empty, which fails proposer-pubkey lookup
// in getPayload for every slot until the next successful refresh, so the refresh is
// abandoned and the previous set kept instead.
var ErrNoKnownValidators = errors.New("beacon node returned no validators")

// ffStreamDecodeKnownValidators selects how the validator set is read from the
// beacon node. Streaming keeps peak memory far lower, but buffering is what this
// has shipped with, so it stays the default: set USE_STREAM_DECODING_GET_VALIDATORS=1
// to opt in, and unset it to revert without a rollback.
var ffStreamDecodeKnownValidators = os.Getenv("USE_STREAM_DECODING_GET_VALIDATORS") == "1"

// knownValidatorsStreamer is the streaming refresh, reached by assertion rather
// than through beaconclient.IMultiBeaconClient so that the streaming path stays
// contained to beaconclient/state_validators_stream.go.
type knownValidatorsStreamer interface {
	StreamStateValidators(stateID string, collector beaconclient.ValidatorCollector) error
}

// knownValidatorsCollector builds the known-validator lookup maps as validators
// arrive from the beacon node.
type knownValidatorsCollector struct {
	byPubkey map[common.PubkeyHex]uint64
	byIndex  map[uint64]common.PubkeyHex
}

func (c *knownValidatorsCollector) Reset() {
	c.byPubkey = make(map[common.PubkeyHex]uint64)
	c.byIndex = make(map[uint64]common.PubkeyHex)
}

func (c *knownValidatorsCollector) Add(index uint64, pubkey string) {
	pk := common.NewPubkeyHex(pubkey)
	c.byPubkey[pk] = index
	c.byIndex[index] = pk
}

// fetchKnownValidators returns the known-validator lookup maps, streaming the
// beacon node response when enabled and falling back to the buffered path
// otherwise. It replaces the fetch-then-build-maps block that
// RefreshKnownValidatorsWithoutChecks used to inline.
func fetchKnownValidators(log *logrus.Entry, beaconClient beaconclient.IMultiBeaconClient) (byPubkey map[common.PubkeyHex]uint64, byIndex map[uint64]common.PubkeyHex, err error) {
	collector := new(knownValidatorsCollector)
	collector.Reset()

	streamed := false
	if ffStreamDecodeKnownValidators {
		if streamer, ok := beaconClient.(knownValidatorsStreamer); ok {
			streamErr := streamer.StreamStateValidators(beaconclient.StateIDHead, collector) // head is fastest
			switch {
			case streamErr == nil:
				streamed = true
			case errors.Is(streamErr, beaconclient.ErrStreamStateValidatorsUnsupported):
				log.Warn("streaming validator refresh is unsupported, falling back to buffered")
			default:
				// A real failure: do not re-run the request on the buffered path, that
				// would double an already very heavy call on the beacon node.
				return nil, nil, streamErr
			}
		}
	}

	if !streamed {
		validators, fetchErr := beaconClient.GetStateValidators(beaconclient.StateIDHead) // head is fastest
		if fetchErr != nil {
			return nil, nil, fetchErr
		}

		collector.Reset()
		for _, valEntry := range validators.Data {
			collector.Add(valEntry.Index, valEntry.Validator.Pubkey)
		}
	}

	if len(collector.byIndex) == 0 {
		return nil, nil, ErrNoKnownValidators
	}
	return collector.byPubkey, collector.byIndex, nil
}
