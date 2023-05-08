package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/jsonrpc"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	ErrRequestClosed    = errors.New("request context closed")
	ErrSimulationFailed = errors.New("simulation failed")
	ErrJSONDecodeFailed = errors.New("json error")

	maxConcurrentBlocks = int64(cli.GetEnvInt("BLOCKSIM_MAX_CONCURRENT", 4)) // 0 for no maximum
	simRequestTimeout   = time.Duration(cli.GetEnvInt("BLOCKSIM_TIMEOUT_MS", 10000)) * time.Millisecond
)

type IBlockSimRateLimiter interface {
	Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (error, error)
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
		},
	}
}

func (b *BlockSimulationRateLimiter) Send(context context.Context, payload *common.BuilderBlockValidationRequest, isHighPrio, fastTrack bool) (requestErr, validationErr error) {
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
		return fmt.Errorf("%w, %w", ErrRequestClosed, err), nil
	}

	var simReq *jsonrpc.JSONRPCRequest
	if payload.Capella != nil {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV2", payload)
	} else if payload.Bellatrix != nil {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV1", payload)
	}
	_, requestErr, validationErr = SendJSONRPCRequest(&b.client, *simReq, b.blockSimURL, isHighPrio, fastTrack)
	return requestErr, validationErr
}

// CurrentCounter returns the number of waiting and active requests
func (b *BlockSimulationRateLimiter) CurrentCounter() int64 {
	return atomic.LoadInt64(&b.counter)
}

// SendJSONRPCRequest sends the request to URL and returns the general JsonRpcResponse, or an error (note: not the JSONRPCError)
func SendJSONRPCRequest(client *http.Client, req jsonrpc.JSONRPCRequest, url string, isHighPrio, fastTrack bool) (res *jsonrpc.JSONRPCResponse, requestErr, validationErr error) {
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
	if isHighPrio {
		httpReq.Header.Add("X-High-Priority", "true")
	}
	if fastTrack {
		httpReq.Header.Add("X-Fast-Track", "true")
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
		return res, nil, fmt.Errorf("%w: %s", ErrSimulationFailed, res.Error.Message)
	}
	return res, nil, nil
}
