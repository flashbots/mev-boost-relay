package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/jsonrpc"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/goccy/go-json"
)

var (
	ErrRequestClosed    = errors.New("request context closed")
	ErrSimulationFailed = errors.New("simulation failed")
	ErrJSONDecodeFailed = errors.New("json error")
	ErrNoCapellaPayload = errors.New("capella payload is nil")
	ErrNoDenebPayload   = errors.New("deneb payload is nil")
	ErrNoElectraPayload = errors.New("electra payload is nil")
	ErrNoFuluPayload    = errors.New("fulu payload is nil")

	maxConcurrentBlocks = int64(cli.GetEnvInt("BLOCKSIM_MAX_CONCURRENT", 4)) // 0 for no maximum
	simRequestTimeout   = time.Duration(cli.GetEnvInt("BLOCKSIM_TIMEOUT_MS", 10000)) * time.Millisecond
)

type IBlockSimRateLimiter interface {
	Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (*common.BuilderBlockValidationResponse, error, error)
	CurrentCounter() int64
}

type BlockSimulationRateLimiter struct {
	cv          *sync.Cond
	counter     int64
	blockSimURL string
	client      http.Client
}

func NewBlockSimulationRateLimiter(blockSimURL string) *BlockSimulationRateLimiter {
	return &BlockSimulationRateLimiter{
		cv:          sync.NewCond(&sync.Mutex{}),
		counter:     0,
		blockSimURL: blockSimURL,
		client: http.Client{ //nolint:exhaustruct
			Timeout: simRequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				MaxConnsPerHost:     100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (b *BlockSimulationRateLimiter) Send(
	context context.Context,
	payload *common.BuilderBlockValidationRequest,
	isHighPrio,
	fastTrack bool,
) (response *common.BuilderBlockValidationResponse, requestErr, validationErr error) {
	b.cv.L.Lock()
	cnt := atomic.AddInt64(&b.counter, 1)
	if maxConcurrentBlocks > 0 && cnt > maxConcurrentBlocks {
		b.cv.Wait()
	}
	b.cv.L.Unlock()

	defer func() {
		b.cv.L.Lock()
		atomic.AddInt64(&b.counter, -1)
		b.cv.Signal()
		b.cv.L.Unlock()
	}()

	if err := context.Err(); err != nil {
		return nil, fmt.Errorf("%w, %w", ErrRequestClosed, err), nil
	}

	var simReq *jsonrpc.JSONRPCRequest
	if payload.Version == spec.DataVersionCapella && payload.Capella == nil {
		return nil, ErrNoCapellaPayload, nil
	}

	if payload.Version == spec.DataVersionDeneb && payload.Deneb == nil {
		return nil, ErrNoDenebPayload, nil
	}

	if payload.Version == spec.DataVersionElectra && payload.Electra == nil {
		return nil, ErrNoElectraPayload, nil
	}

	if payload.Version == spec.DataVersionFulu && payload.Fulu == nil {
		return nil, ErrNoFuluPayload, nil
	}

	submission, err := common.GetBlockSubmissionInfo(payload.VersionedSubmitBlockRequest)
	if err != nil {
		return nil, err, nil
	}

	// Prepare headers
	headers := http.Header{}
	headers.Add("X-Request-ID", fmt.Sprintf("%d/%s", submission.BidTrace.Slot, submission.BidTrace.BlockHash.String()))
	if isHighPrio {
		headers.Add("X-High-Priority", "true")
	}
	if fastTrack {
		headers.Add("X-Fast-Track", "true")
	}

	// Create and fire off JSON-RPC request
	// TODO - bharath: Does the electra flashbots_validateBuilderSubmissionV4 work for fulu?
	if payload.Version == spec.DataVersionElectra || payload.Version == spec.DataVersionFulu {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV4", payload)
	} else if payload.Version == spec.DataVersionDeneb {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV3", payload)
	} else {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV2", payload)
	}
	res, requestErr, validationErr := SendJSONRPCRequest(&b.client, *simReq, b.blockSimURL, headers)
	response = new(common.BuilderBlockValidationResponse)
	if res != nil {
		if err := json.Unmarshal(res.Result, response); err != nil {
			return nil, fmt.Errorf("unable to unmarshal response: %w", err), validationErr
		}
	}
	return response, requestErr, validationErr
}

// CurrentCounter returns the number of waiting and active requests
func (b *BlockSimulationRateLimiter) CurrentCounter() int64 {
	return atomic.LoadInt64(&b.counter)
}

// SendJSONRPCRequest sends the request to URL and returns the general JsonRpcResponse, or an error (note: not the JSONRPCError)
func SendJSONRPCRequest(client *http.Client, req jsonrpc.JSONRPCRequest, url string, headers http.Header) (res *jsonrpc.JSONRPCResponse, requestErr, validationErr error) {
	buf, err := json.Marshal(req)
	if err != nil {
		return nil, err, nil
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err, nil
	}

	// set request headers
	httpReq.Header.Add("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Add(k, v[0])
	}

	// execute request
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err, nil
	}
	defer resp.Body.Close()

	// read all resp bytes
	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response bytes: %w", err), nil
	}

	// try json parsing
	res = new(jsonrpc.JSONRPCResponse)
	if err := json.NewDecoder(bytes.NewReader(rawResp)).Decode(res); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJSONDecodeFailed, string(rawResp[:])), nil
	}

	if res.Error != nil {
		if res.Error.Data != nil {
			return res, nil, fmt.Errorf("%w: %s (%v)", ErrSimulationFailed, res.Error.Message, res.Error.Data)
		}
		return res, nil, fmt.Errorf("%w: %s", ErrSimulationFailed, res.Error.Message)
	}
	return res, nil, nil
}
