package common

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	capellaspec "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

var (
	ErrInvalidForkVersion = errors.New("invalid fork version")
	ErrHTTPErrorResponse  = errors.New("got an HTTP error response")
	ErrIncorrectLength    = errors.New("incorrect length")
)

// SlotPos returns the slot's position in the epoch (1-based, i.e. 1..32)
func SlotPos(slot uint64) uint64 {
	return (slot % SlotsPerEpoch) + 1
}

func makeRequest(ctx context.Context, client http.Client, method, url string, payload any) (*http.Response, error) {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return nil, err2
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))
	}
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return resp, fmt.Errorf("%w: %d / %s", ErrHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	return resp, nil
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType phase0.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain phase0.Domain, err error) {
	genesisValidatorsRoot := phase0.Root(ethcommon.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, ErrInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return ssz.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

func GetEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func GetSliceEnv(key string, defaultValue []string) []string {
	if value, ok := os.LookupEnv(key); ok {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func GetIPXForwardedFor(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		if strings.Contains(forwarded, ",") { // return first entry of list of IPs
			return strings.Split(forwarded, ",")[0]
		}
		return forwarded
	}
	return r.RemoteAddr
}

// GetMevBoostVersionFromUserAgent returns the mev-boost version from an user agent string
// Example ua: "mev-boost/1.0.1 go-http-client" -> returns "1.0.1". If no version is found, returns "-"
func GetMevBoostVersionFromUserAgent(ua string) string {
	parts := strings.Split(ua, " ")
	if strings.HasPrefix(parts[0], "mev-boost") {
		parts2 := strings.Split(parts[0], "/")
		if len(parts2) == 2 {
			return parts2[1]
		}
	}
	return "-"
}

func U256StrToUint256(s types.U256Str) *uint256.Int {
	i := new(uint256.Int)
	i.SetBytes(reverse(s[:]))
	return i
}

func reverse(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := len(dst)/2 - 1; i >= 0; i-- {
		opp := len(dst) - 1 - i
		dst[i], dst[opp] = dst[opp], dst[i]
	}
	return dst
}

// GetEnvStrSlice returns a slice of strings from a comma-separated env var
func GetEnvStrSlice(key string, defaultValue []string) []string {
	if value, ok := os.LookupEnv(key); ok {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func StrToPhase0Pubkey(s string) (ret phase0.BLSPubKey, err error) {
	pubkeyBytes, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return ret, err
	}
	if len(pubkeyBytes) != phase0.PublicKeyLength {
		return ret, ErrIncorrectLength
	}
	copy(ret[:], pubkeyBytes)
	return ret, nil
}

func StrToPhase0Hash(s string) (ret phase0.Hash32, err error) {
	hashBytes, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return ret, err
	}
	if len(hashBytes) != phase0.Hash32Length {
		return ret, ErrIncorrectLength
	}
	copy(ret[:], hashBytes)
	return ret, nil
}

type CreateTestBlockSubmissionOpts struct {
	relaySk bls.SecretKey
	relayPk phase0.BLSPubKey
	domain  phase0.Domain

	Slot           uint64
	ParentHash     string
	ProposerPubkey string
}

func CreateTestBlockSubmission(t *testing.T, builderPubkey string, value *uint256.Int, opts *CreateTestBlockSubmissionOpts) (payload *spec.VersionedSubmitBlockRequest, getPayloadResponse *api.VersionedExecutionPayload, getHeaderResponse *spec.VersionedSignedBuilderBid) {
	t.Helper()
	var err error

	slot := uint64(0)
	relaySk := bls.SecretKey{}
	relayPk := phase0.BLSPubKey{}
	domain := phase0.Domain{}
	proposerPk := phase0.BLSPubKey{}
	parentHash := phase0.Hash32{}

	if opts != nil {
		relaySk = opts.relaySk
		relayPk = opts.relayPk
		domain = opts.domain
		slot = opts.Slot

		if opts.ProposerPubkey != "" {
			proposerPk, err = StrToPhase0Pubkey(opts.ProposerPubkey)
			require.NoError(t, err)
		}

		if opts.ParentHash != "" {
			parentHash, err = StrToPhase0Hash(opts.ParentHash)
			require.NoError(t, err)
		}
	}

	builderPk, err := StrToPhase0Pubkey(builderPubkey)
	require.NoError(t, err)

	payload = &spec.VersionedSubmitBlockRequest{ //nolint:exhaustruct
		Version: consensusspec.DataVersionCapella,
		Capella: &capella.SubmitBlockRequest{
			Message: &apiv1.BidTrace{ //nolint:exhaustruct
				BuilderPubkey:  builderPk,
				Value:          value,
				Slot:           slot,
				ParentHash:     parentHash,
				ProposerPubkey: proposerPk,
			},
			ExecutionPayload: &capellaspec.ExecutionPayload{}, //nolint:exhaustruct
			Signature:        phase0.BLSSignature{},
		},
	}

	getHeaderResponse, err = BuildGetHeaderResponse(payload, &relaySk, &relayPk, domain)
	require.NoError(t, err)

	getPayloadResponse, err = BuildGetPayloadResponse(payload)
	require.NoError(t, err)

	return payload, getPayloadResponse, getHeaderResponse
}

// GetEnvDurationSec returns the value of the environment variable as duration in seconds,
// or defaultValue if the environment variable doesn't exist or is not a valid integer
func GetEnvDurationSec(key string, defaultValueSec int) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		val, err := strconv.Atoi(value)
		if err != nil {
			return time.Duration(val) * time.Second
		}
	}
	return time.Duration(defaultValueSec) * time.Second
}

func GetBlockSubmissionInfo(submission *spec.VersionedSubmitBlockRequest) (*BlockSubmissionInfo, error) {
	bidTrace, err := submission.BidTrace()
	if err != nil {
		return nil, err
	}
	signature, err := submission.Signature()
	if err != nil {
		return nil, err
	}
	slot, err := submission.Slot()
	if err != nil {
		return nil, err
	}
	blockHash, err := submission.BlockHash()
	if err != nil {
		return nil, err
	}
	parentHash, err := submission.ParentHash()
	if err != nil {
		return nil, err
	}
	executionPayloadBlockHash, err := submission.ExecutionPayloadBlockHash()
	if err != nil {
		return nil, err
	}
	executionPayloadParentHash, err := submission.ExecutionPayloadParentHash()
	if err != nil {
		return nil, err
	}
	builder, err := submission.Builder()
	if err != nil {
		return nil, err
	}
	proposerPubkey, err := submission.ProposerPubKey()
	if err != nil {
		return nil, err
	}
	proposerFeeRecipient, err := submission.ProposerFeeRecipient()
	if err != nil {
		return nil, err
	}
	gasUsed, err := submission.GasUsed()
	if err != nil {
		return nil, err
	}
	gasLimit, err := submission.GasLimit()
	if err != nil {
		return nil, err
	}
	timestamp, err := submission.Timestamp()
	if err != nil {
		return nil, err
	}
	txs, err := submission.Transactions()
	if err != nil {
		return nil, err
	}
	value, err := submission.Value()
	if err != nil {
		return nil, err
	}
	blockNumber, err := submission.BlockNumber()
	if err != nil {
		return nil, err
	}
	prevRandao, err := submission.PrevRandao()
	if err != nil {
		return nil, err
	}
	withdrawals, err := submission.Withdrawals()
	if err != nil {
		return nil, err
	}
	return &BlockSubmissionInfo{
		BidTrace:                   bidTrace,
		Signature:                  signature,
		Slot:                       slot,
		BlockHash:                  blockHash,
		ParentHash:                 parentHash,
		ExecutionPayloadBlockHash:  executionPayloadBlockHash,
		ExecutionPayloadParentHash: executionPayloadParentHash,
		Builder:                    builder,
		Proposer:                   proposerPubkey,
		ProposerFeeRecipient:       proposerFeeRecipient,
		GasUsed:                    gasUsed,
		GasLimit:                   gasLimit,
		Timestamp:                  timestamp,
		Transactions:               txs,
		Value:                      value,
		PrevRandao:                 prevRandao,
		BlockNumber:                blockNumber,
		Withdrawals:                withdrawals,
	}, nil
}

func GetBlockSubmissionExecutionPayload(submission *spec.VersionedSubmitBlockRequest) (*api.VersionedExecutionPayload, error) {
	if submission.Capella != nil {
		return &api.VersionedExecutionPayload{
			Version: consensusspec.DataVersionCapella,
			Capella: submission.Capella.ExecutionPayload,
		}, nil
	}
	return nil, ErrEmptyPayload
}
