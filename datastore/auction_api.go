package datastore

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/pkg/errors"
)

var ErrFailedToParsePayload = errors.New("failed to parse payload")

func getPayloadContents(slot uint64, proposerPubkey, blockHash, host, basePath, authToken string, timeout time.Duration) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	client := &http.Client{Timeout: timeout}

	queryParams := url.Values{}
	queryParams.Add("slot", fmt.Sprintf("%d", slot))
	queryParams.Add("proposer_pubkey", proposerPubkey)
	queryParams.Add("block_hash", blockHash)

	fullURL := fmt.Sprintf("%s/%s/payload_contents?%s", host, basePath, queryParams.Encode())
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create payload contents request")
	}

	// Add auth token if provided
	if authToken != "" {
		req.Header.Add("x-auth-token", authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch payload contents")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrExecutionPayloadNotFound
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read payload contents response body")
	}

	// Try to parse deneb contents
	denebPayloadContents := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
	err = denebPayloadContents.UnmarshalSSZ(body)

	if err == nil {
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionDeneb,
			Deneb:   denebPayloadContents,
		}, nil
	}

	// Try to parse capella payload
	capellaPayload := new(capella.ExecutionPayload)
	err = capellaPayload.UnmarshalSSZ(body)

	if err == nil {
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionCapella,
			Capella: capellaPayload,
		}, nil
	}

	return nil, ErrFailedToParsePayload
}

func (ds *Datastore) LocalPayloadContents(slot uint64, proposerPubkey, blockHash string) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	return getPayloadContents(slot, proposerPubkey, blockHash, ds.localAuctionHost, "internal", "", 0)
}

func (ds *Datastore) RemotePayloadContents(slot uint64, proposerPubkey, blockHash string) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	return getPayloadContents(slot, proposerPubkey, blockHash, ds.remoteAuctionHost, "private", ds.auctionAuthToken, 1*time.Second)
}

func getBidTrace(slot uint64, proposerPubkey, blockHash, auctionHost, basePath, authToken string) (*common.BidTraceV2, error) {
	client := &http.Client{}

	queryParams := url.Values{}
	queryParams.Add("slot", fmt.Sprintf("%d", slot))
	queryParams.Add("proposer_pubkey", proposerPubkey)
	queryParams.Add("block_hash", blockHash)

	fullURL := fmt.Sprintf("%s/%s/bid_trace?%s", auctionHost, basePath, queryParams.Encode())
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create bid trace request")
	}

	if authToken != "" {
		req.Header.Add("x-auth-token", authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrBidTraceNotFound
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read bit trace response body")
	}

	bidtrace := new(common.BidTraceV2)
	err = json.Unmarshal(body, &bidtrace)
	if err != nil {
		return nil, err
	}

	return bidtrace, nil
}

func (ds *Datastore) LocalBidTrace(slot uint64, proposerPubkey, blockHash string) (*common.BidTraceV2, error) {
	return getBidTrace(slot, proposerPubkey, blockHash, ds.localAuctionHost, "internal", "")
}

func (ds *Datastore) RemoteBidTrace(slot uint64, proposerPubkey, blockHash string) (*common.BidTraceV2, error) {
	return getBidTrace(slot, proposerPubkey, blockHash, ds.remoteAuctionHost, "private", ds.auctionAuthToken)
}
