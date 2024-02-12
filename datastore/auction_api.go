package datastore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/pkg/errors"
)

const API_ROOT = "http://turbo-auction-api"

var ErrFailedToParsePayload = errors.New("failed to parse payload")

func GetPayloadContents(slot uint64, proposerPubkey, blockHash string) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	queryParams := url.Values{}
	queryParams.Add("slot", fmt.Sprintf("%d", slot))
	queryParams.Add("proposer_pubkey", proposerPubkey)
	queryParams.Add("block_hash", blockHash)

	fullUrl := fmt.Sprintf("%s/internal/payload_contents?%s", API_ROOT, queryParams.Encode())

	var err error

	resp, err := http.Get(fullUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, ErrExecutionPayloadNotFound
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Try to parse deneb contents
	denebPayloadContents := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
	err = denebPayloadContents.UnmarshalSSZ([]byte(body))

	if err == nil {
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionDeneb,
			Deneb:   denebPayloadContents,
		}, nil
	}

	// Try to parse capella payload
	capellaPayload := new(capella.ExecutionPayload)
	err = capellaPayload.UnmarshalSSZ([]byte(body))

	if err == nil {
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionCapella,
			Capella: capellaPayload,
		}, nil
	}

	return nil, ErrFailedToParsePayload
}

func GetBidTrace(slot uint64, proposerPubkey, blockHash string) (*common.BidTraceV2, error) {
	queryParams := url.Values{}
	queryParams.Add("slot", fmt.Sprintf("%d", slot))
	queryParams.Add("proposer_pubkey", proposerPubkey)
	queryParams.Add("block_hash", blockHash)

	fullUrl := fmt.Sprintf("%s/internal/bid_trace?%s", API_ROOT, queryParams.Encode())

	var err error

	resp, err := http.Get(fullUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, ErrBidTraceNotFound
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bidtrace := new(common.BidTraceV2)
	err = json.Unmarshal(body, &bidtrace)
	if err != nil {
		return nil, err
	}

	return bidtrace, nil
}
