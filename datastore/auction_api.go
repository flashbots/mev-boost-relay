package datastore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	builderApi "github.com/attestantio/go-builder-client/api"
	"github.com/flashbots/mev-boost-relay/common"
)

const API_ROOT = "http://turbo-auction-api"

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

	payload := new(builderApi.VersionedSubmitBlindedBlockResponse)
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
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
