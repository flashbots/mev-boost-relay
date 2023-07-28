package datastore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix = "boost-relay"

	expiryBidCache = 45 * time.Second

	RedisConfigFieldPubkey         = "pubkey"
	RedisStatsFieldLatestSlot      = "latest-slot"
	RedisStatsFieldValidatorsTotal = "validators-total"

	ErrFailedUpdatingTopBidNoBids            = errors.New("failed to update top bid because no bids were found")
	ErrAnotherPayloadAlreadyDeliveredForSlot = errors.New("another payload block hash for slot was already delivered")
	ErrPastSlotAlreadyDelivered              = errors.New("payload for past slot was already delivered")

	// Docs about redis settings: https://redis.io/docs/reference/clients/
	redisConnectionPoolSize = cli.GetEnvInt("REDIS_CONNECTION_POOL_SIZE", 0) // 0 means use default (10 per CPU)
	redisMinIdleConnections = cli.GetEnvInt("REDIS_MIN_IDLE_CONNECTIONS", 0) // 0 means use default
	redisReadTimeoutSec     = cli.GetEnvInt("REDIS_READ_TIMEOUT_SEC", 0)     // 0 means use default (3 sec)
	redisPoolTimeoutSec     = cli.GetEnvInt("REDIS_POOL_TIMEOUT_SEC", 0)     // 0 means use default (ReadTimeout + 1 sec)
	redisWriteTimeoutSec    = cli.GetEnvInt("REDIS_WRITE_TIMEOUT_SEC", 0)    // 0 means use default (3 seconds)
)

func connectRedis(redisURI string) (*redis.Client, error) {
	// Handle both URIs and full URLs, assume unencrypted connections
	if !strings.HasPrefix(redisURI, "redis://") && !strings.HasPrefix(redisURI, "rediss://") {
		redisURI = "redis://" + redisURI
	}

	redisOpts, err := redis.ParseURL(redisURI)
	if err != nil {
		return nil, err
	}

	if redisConnectionPoolSize > 0 {
		redisOpts.PoolSize = redisConnectionPoolSize
	}
	if redisMinIdleConnections > 0 {
		redisOpts.MinIdleConns = redisMinIdleConnections
	}
	if redisReadTimeoutSec > 0 {
		redisOpts.ReadTimeout = time.Duration(redisReadTimeoutSec) * time.Second
	}
	if redisPoolTimeoutSec > 0 {
		redisOpts.PoolTimeout = time.Duration(redisPoolTimeoutSec) * time.Second
	}
	if redisWriteTimeoutSec > 0 {
		redisOpts.WriteTimeout = time.Duration(redisWriteTimeoutSec) * time.Second
	}

	redisClient := redis.NewClient(redisOpts)
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		// unable to connect to redis
		return nil, err
	}
	return redisClient, nil
}

type RedisCache struct {
	client         *redis.Client
	readonlyClient *redis.Client

	// prefixes (keys generated with a function)
	prefixGetHeaderResponse           string
	prefixExecPayloadCapella          string
	prefixBidTrace                    string
	prefixBlockBuilderLatestBids      string // latest bid for a given slot
	prefixBlockBuilderLatestBidsValue string // value of latest bid for a given slot
	prefixBlockBuilderLatestBidsTime  string // when the request was received, to avoid older requests overwriting newer ones after a slot validation
	prefixTopBidValue                 string
	prefixFloorBid                    string
	prefixFloorBidValue               string

	// keys
	keyValidatorRegistrationTimestamp string

	keyRelayConfig        string
	keyStats              string
	keyProposerDuties     string
	keyBlockBuilderStatus string
	keyLastSlotDelivered  string
	keyLastHashDelivered  string
}

func NewRedisCache(prefix, redisURI, readonlyURI string) (*RedisCache, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	roClient := client
	if readonlyURI != "" {
		roClient, err = connectRedis(readonlyURI)
		if err != nil {
			return nil, err
		}
	}

	return &RedisCache{
		client:         client,
		readonlyClient: roClient,

		prefixGetHeaderResponse:  fmt.Sprintf("%s/%s:cache-gethead-response", redisPrefix, prefix),
		prefixExecPayloadCapella: fmt.Sprintf("%s/%s:cache-execpayload-capella", redisPrefix, prefix),
		prefixBidTrace:           fmt.Sprintf("%s/%s:cache-bid-trace", redisPrefix, prefix),

		prefixBlockBuilderLatestBids:      fmt.Sprintf("%s/%s:block-builder-latest-bid", redisPrefix, prefix),       // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsValue: fmt.Sprintf("%s/%s:block-builder-latest-bid-value", redisPrefix, prefix), // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsTime:  fmt.Sprintf("%s/%s:block-builder-latest-bid-time", redisPrefix, prefix),  // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixTopBidValue:                 fmt.Sprintf("%s/%s:top-bid-value", redisPrefix, prefix),                  // prefix:slot_parentHash_proposerPubkey
		prefixFloorBid:                    fmt.Sprintf("%s/%s:bid-floor", redisPrefix, prefix),                      // prefix:slot_parentHash_proposerPubkey
		prefixFloorBidValue:               fmt.Sprintf("%s/%s:bid-floor-value", redisPrefix, prefix),                // prefix:slot_parentHash_proposerPubkey

		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validator-registration-timestamp", redisPrefix, prefix),
		keyRelayConfig:                    fmt.Sprintf("%s/%s:relay-config", redisPrefix, prefix),

		keyStats:              fmt.Sprintf("%s/%s:stats", redisPrefix, prefix),
		keyProposerDuties:     fmt.Sprintf("%s/%s:proposer-duties", redisPrefix, prefix),
		keyBlockBuilderStatus: fmt.Sprintf("%s/%s:block-builder-status", redisPrefix, prefix),
		keyLastSlotDelivered:  fmt.Sprintf("%s/%s:last-slot-delivered", redisPrefix, prefix),
		keyLastHashDelivered:  fmt.Sprintf("%s/%s:last-hash-delivered", redisPrefix, prefix),
	}, nil
}

func (r *RedisCache) keyCacheGetHeaderResponse(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixGetHeaderResponse, slot, parentHash, proposerPubkey)
}

func (r *RedisCache) keyExecPayloadCapella(slot uint64, proposerPubkey, blockHash string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixExecPayloadCapella, slot, proposerPubkey, blockHash)
}

func (r *RedisCache) keyCacheBidTrace(slot uint64, proposerPubkey, blockHash string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBidTrace, slot, proposerPubkey, blockHash)
}

// keyLatestBidByBuilder returns the key for the getHeader response the latest bid by a specific builder
func (r *RedisCache) keyLatestBidByBuilder(slot uint64, parentHash, proposerPubkey, builderPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s/%s", r.prefixBlockBuilderLatestBids, slot, parentHash, proposerPubkey, builderPubkey)
}

// keyBlockBuilderLatestBidValue returns the hashmap key for the value of the latest bid by a specific builder
func (r *RedisCache) keyBlockBuilderLatestBidsValue(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBlockBuilderLatestBidsValue, slot, parentHash, proposerPubkey)
}

// keyBlockBuilderLatestBidValue returns the hashmap key for the time of the latest bid by a specific builder
func (r *RedisCache) keyBlockBuilderLatestBidsTime(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBlockBuilderLatestBidsTime, slot, parentHash, proposerPubkey)
}

// keyTopBidValue returns the hashmap key for the time of the latest bid by a specific builder
func (r *RedisCache) keyTopBidValue(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixTopBidValue, slot, parentHash, proposerPubkey)
}

// keyFloorBid returns the key for the highest non-cancellable bid of a given slot+parentHash+proposerPubkey
func (r *RedisCache) keyFloorBid(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixFloorBid, slot, parentHash, proposerPubkey)
}

// keyFloorBidValue returns the key for the highest non-cancellable value of a given slot+parentHash+proposerPubkey
func (r *RedisCache) keyFloorBidValue(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixFloorBidValue, slot, parentHash, proposerPubkey)
}

func (r *RedisCache) GetObj(key string, obj any) (err error) {
	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), &obj)
}

func (r *RedisCache) SetObj(key string, value any, expiration time.Duration) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(context.Background(), key, marshalledValue, expiration).Err()
}

// SetObjPipelined saves an object in the given Redis key on a Redis pipeline (JSON encoded)
func (r *RedisCache) SetObjPipelined(ctx context.Context, tx redis.Pipeliner, key string, value any, expiration time.Duration) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return tx.Set(ctx, key, marshalledValue, expiration).Err()
}

func (r *RedisCache) HSetObj(key, field string, value any, expiration time.Duration) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	err = r.client.HSet(context.Background(), key, field, marshalledValue).Err()
	if err != nil {
		return err
	}

	return r.client.Expire(context.Background(), key, expiration).Err()
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(proposerPubkey common.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.HGet(context.Background(), r.keyValidatorRegistrationTimestamp, strings.ToLower(proposerPubkey.String())).Uint64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistrationTimestampIfNewer(proposerPubkey common.PubkeyHex, timestamp uint64) error {
	knownTimestamp, err := r.GetValidatorRegistrationTimestamp(proposerPubkey)
	if err != nil {
		return err
	}
	if knownTimestamp >= timestamp {
		return nil
	}
	return r.SetValidatorRegistrationTimestamp(proposerPubkey, timestamp)
}

func (r *RedisCache) SetValidatorRegistrationTimestamp(proposerPubkey common.PubkeyHex, timestamp uint64) error {
	return r.client.HSet(context.Background(), r.keyValidatorRegistrationTimestamp, proposerPubkey.String(), timestamp).Err()
}

func (r *RedisCache) CheckAndSetLastSlotAndHashDelivered(slot uint64, hash string) (err error) {
	// More details about Redis optimistic locking:
	// - https://redis.uptrace.dev/guide/go-redis-pipelines.html#transactions
	// - https://github.com/redis/go-redis/blob/6ecbcf6c90919350c42181ce34c1cbdfbd5d1463/race_test.go#L183
	txf := func(tx *redis.Tx) error {
		lastSlotDelivered, err := tx.Get(context.Background(), r.keyLastSlotDelivered).Uint64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}

		// slot in the past, reject request
		if slot < lastSlotDelivered {
			return ErrPastSlotAlreadyDelivered
		}

		// current slot, reject request if hash is different
		if slot == lastSlotDelivered {
			lastHashDelivered, err := tx.Get(context.Background(), r.keyLastHashDelivered).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return err
			}
			if hash != lastHashDelivered {
				return ErrAnotherPayloadAlreadyDeliveredForSlot
			}
			return nil
		}

		_, err = tx.TxPipelined(context.Background(), func(pipe redis.Pipeliner) error {
			pipe.Set(context.Background(), r.keyLastSlotDelivered, slot, 0)
			pipe.Set(context.Background(), r.keyLastHashDelivered, hash, 0)
			return nil
		})

		return err
	}

	return r.client.Watch(context.Background(), txf, r.keyLastSlotDelivered, r.keyLastHashDelivered)
}

func (r *RedisCache) GetLastSlotDelivered(ctx context.Context, tx redis.Pipeliner) (slot uint64, err error) {
	c := tx.Get(ctx, r.keyLastSlotDelivered)
	_, err = tx.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return c.Uint64()
}

func (r *RedisCache) GetLastHashDelivered() (hash string, err error) {
	return r.client.Get(context.Background(), r.keyLastHashDelivered).Result()
}

func (r *RedisCache) SetStats(field string, value any) (err error) {
	return r.client.HSet(context.Background(), r.keyStats, field, value).Err()
}

func (r *RedisCache) GetStats(field string) (value string, err error) {
	return r.client.HGet(context.Background(), r.keyStats, field).Result()
}

// GetStatsUint64 returns (valueUint64, nil), or (0, redis.Nil) if the field does not exist
func (r *RedisCache) GetStatsUint64(field string) (value uint64, err error) {
	valStr, err := r.client.HGet(context.Background(), r.keyStats, field).Result()
	if err != nil {
		return 0, err
	}

	value, err = strconv.ParseUint(valStr, 10, 64)
	return value, err
}

func (r *RedisCache) SetProposerDuties(proposerDuties []common.BuilderGetValidatorsResponseEntry) (err error) {
	return r.SetObj(r.keyProposerDuties, proposerDuties, 0)
}

func (r *RedisCache) GetProposerDuties() (proposerDuties []common.BuilderGetValidatorsResponseEntry, err error) {
	proposerDuties = make([]common.BuilderGetValidatorsResponseEntry, 0)
	err = r.GetObj(r.keyProposerDuties, &proposerDuties)
	if errors.Is(err, redis.Nil) {
		return proposerDuties, nil
	}
	return proposerDuties, err
}

func (r *RedisCache) SetRelayConfig(field, value string) (err error) {
	return r.client.HSet(context.Background(), r.keyRelayConfig, field, value).Err()
}

func (r *RedisCache) GetRelayConfig(field string) (string, error) {
	res, err := r.client.HGet(context.Background(), r.keyRelayConfig, field).Result()
	if errors.Is(err, redis.Nil) {
		return res, nil
	}
	return res, err
}

func (r *RedisCache) GetBestBid(slot uint64, parentHash, proposerPubkey string) (*spec.VersionedSignedBuilderBid, error) {
	key := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	resp := new(spec.VersionedSignedBuilderBid)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SaveExecutionPayloadCapella(ctx context.Context, tx redis.Pipeliner, slot uint64, proposerPubkey, blockHash string, execPayload *capella.ExecutionPayload) (err error) {
	key := r.keyExecPayloadCapella(slot, proposerPubkey, blockHash)
	b, err := execPayload.MarshalSSZ()
	if err != nil {
		return err
	}
	return tx.Set(ctx, key, b, expiryBidCache).Err()
}

func (r *RedisCache) GetExecutionPayloadCapella(slot uint64, proposerPubkey, blockHash string) (*api.VersionedExecutionPayload, error) {
	capellaPayload := new(capella.ExecutionPayload)

	key := r.keyExecPayloadCapella(slot, proposerPubkey, blockHash)
	val, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		return nil, err
	}

	err = capellaPayload.UnmarshalSSZ([]byte(val))
	if err != nil {
		return nil, err
	}

	return &api.VersionedExecutionPayload{
		Version: consensusspec.DataVersionCapella,
		Capella: capellaPayload,
	}, nil
}

func (r *RedisCache) SaveBidTrace(ctx context.Context, tx redis.Pipeliner, trace *common.BidTraceV2) (err error) {
	key := r.keyCacheBidTrace(trace.Slot, trace.ProposerPubkey.String(), trace.BlockHash.String())
	return r.SetObjPipelined(ctx, tx, key, trace, expiryBidCache)
}

// GetBidTrace returns (trace, nil), or (nil, redis.Nil) if the trace does not exist
func (r *RedisCache) GetBidTrace(slot uint64, proposerPubkey, blockHash string) (*common.BidTraceV2, error) {
	key := r.keyCacheBidTrace(slot, proposerPubkey, blockHash)
	resp := new(common.BidTraceV2)
	err := r.GetObj(key, resp)
	return resp, err
}

func (r *RedisCache) GetBuilderLatestPayloadReceivedAt(ctx context.Context, tx redis.Pipeliner, slot uint64, builderPubkey, parentHash, proposerPubkey string) (int64, error) {
	keyLatestBidsTime := r.keyBlockBuilderLatestBidsTime(slot, parentHash, proposerPubkey)
	c := tx.HGet(context.Background(), keyLatestBidsTime, builderPubkey)
	_, err := tx.Exec(ctx)
	if errors.Is(err, redis.Nil) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return c.Int64()
}

// SaveBuilderBid saves the latest bid by a specific builder. TODO: use transaction to make these writes atomic
func (r *RedisCache) SaveBuilderBid(ctx context.Context, tx redis.Pipeliner, slot uint64, parentHash, proposerPubkey, builderPubkey string, receivedAt time.Time, headerResp *spec.VersionedSignedBuilderBid) (err error) {
	// save the actual bid
	keyLatestBid := r.keyLatestBidByBuilder(slot, parentHash, proposerPubkey, builderPubkey)
	err = r.SetObjPipelined(ctx, tx, keyLatestBid, headerResp, expiryBidCache)
	if err != nil {
		return err
	}

	// set the time of the request
	keyLatestBidsTime := r.keyBlockBuilderLatestBidsTime(slot, parentHash, proposerPubkey)
	err = tx.HSet(ctx, keyLatestBidsTime, builderPubkey, receivedAt.UnixMilli()).Err()
	if err != nil {
		return err
	}
	err = tx.Expire(ctx, keyLatestBidsTime, expiryBidCache).Err()
	if err != nil {
		return err
	}

	// set the value last, because that's iterated over when updating the best bid, and the payload has to be available
	keyLatestBidsValue := r.keyBlockBuilderLatestBidsValue(slot, parentHash, proposerPubkey)
	value, err := headerResp.Value()
	if err != nil {
		return err
	}
	err = tx.HSet(ctx, keyLatestBidsValue, builderPubkey, value.ToBig().String()).Err()
	if err != nil {
		return err
	}
	return tx.Expire(ctx, keyLatestBidsValue, expiryBidCache).Err()
}

type SaveBidAndUpdateTopBidResponse struct {
	WasBidSaved      bool // Whether this bid was saved
	WasTopBidUpdated bool // Whether the top bid was updated
	IsNewTopBid      bool // Whether the submitted bid became the new top bid

	TopBidValue     *big.Int
	PrevTopBidValue *big.Int

	TimePrep         time.Duration
	TimeSavePayload  time.Duration
	TimeSaveBid      time.Duration
	TimeSaveTrace    time.Duration
	TimeUpdateTopBid time.Duration
	TimeUpdateFloor  time.Duration
}

func (r *RedisCache) SaveBidAndUpdateTopBid(ctx context.Context, tx redis.Pipeliner, trace *common.BidTraceV2, payload *spec.VersionedSubmitBlockRequest, getPayloadResponse *api.VersionedExecutionPayload, getHeaderResponse *spec.VersionedSignedBuilderBid, reqReceivedAt time.Time, isCancellationEnabled bool, floorValue *big.Int) (state SaveBidAndUpdateTopBidResponse, err error) {
	var prevTime, nextTime time.Time
	prevTime = time.Now()

	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		return state, err
	}

	// Load latest bids for a given slot+parent+proposer
	builderBids, err := NewBuilderBidsFromRedis(ctx, r, tx, submission.Slot, submission.ParentHash.String(), submission.Proposer.String())
	if err != nil {
		return state, err
	}

	// Load floor value (if not passed in already)
	if floorValue == nil {
		floorValue, err = r.GetFloorBidValue(ctx, tx, submission.Slot, submission.ParentHash.String(), submission.Proposer.String())
		if err != nil {
			return state, err
		}
	}

	// Get the reference top bid value
	_, state.TopBidValue = builderBids.getTopBid()
	if floorValue.Cmp(state.TopBidValue) == 1 {
		state.TopBidValue = floorValue
	}
	state.PrevTopBidValue = state.TopBidValue

	// Abort now if non-cancellation bid is lower than floor value
	isBidAboveFloor := submission.Value.ToBig().Cmp(floorValue) == 1
	if !isCancellationEnabled && !isBidAboveFloor {
		return state, nil
	}

	// Record time needed
	nextTime = time.Now().UTC()
	state.TimePrep = nextTime.Sub(prevTime)
	prevTime = nextTime

	//
	// Time to save things in Redis
	//
	// 1. Save the execution payload
	err = r.SaveExecutionPayloadCapella(ctx, tx, submission.Slot, submission.ParentHash.String(), submission.Proposer.String(), getPayloadResponse.Capella)
	if err != nil {
		return state, err
	}

	// Record time needed to save payload
	nextTime = time.Now().UTC()
	state.TimeSavePayload = nextTime.Sub(prevTime)
	prevTime = nextTime

	// 2. Save latest bid for this builder
	err = r.SaveBuilderBid(ctx, tx, submission.Slot, submission.ParentHash.String(), submission.Proposer.String(), submission.Builder.String(), reqReceivedAt, getHeaderResponse)
	if err != nil {
		return state, err
	}
	state.WasBidSaved = true
	builderBids.bidValues[submission.Builder.String()] = submission.Value.ToBig()

	// Record time needed to save bid
	nextTime = time.Now().UTC()
	state.TimeSaveBid = nextTime.Sub(prevTime)
	prevTime = nextTime

	// 3. Save the bid trace
	err = r.SaveBidTrace(ctx, tx, trace)
	if err != nil {
		return state, err
	}

	// Record time needed to save trace
	nextTime = time.Now().UTC()
	state.TimeSaveTrace = nextTime.Sub(prevTime)
	prevTime = nextTime

	// If top bid value hasn't change, abort now
	_, state.TopBidValue = builderBids.getTopBid()
	if state.TopBidValue.Cmp(state.PrevTopBidValue) == 0 {
		return state, nil
	}

	state, err = r._updateTopBid(ctx, tx, state, builderBids, submission.Slot, submission.ParentHash.String(), submission.Proposer.String(), floorValue)
	if err != nil {
		return state, err
	}
	state.IsNewTopBid = submission.Value.ToBig().Cmp(state.TopBidValue) == 0

	// Record time needed to update top bid
	nextTime = time.Now().UTC()
	state.TimeUpdateTopBid = nextTime.Sub(prevTime)
	prevTime = nextTime

	if isCancellationEnabled || !isBidAboveFloor {
		return state, nil
	}

	// Non-cancellable bid above floor should set new floor
	keyBidSource := r.keyLatestBidByBuilder(submission.Slot, submission.ParentHash.String(), submission.Proposer.String(), submission.Builder.String())
	keyFloorBid := r.keyFloorBid(submission.Slot, submission.ParentHash.String(), submission.Proposer.String())
	c := tx.Copy(ctx, keyBidSource, keyFloorBid, 0, true)
	_, err = tx.Exec(ctx)
	if err != nil {
		return state, err
	}

	wasCopied, copyErr := c.Result()
	if copyErr != nil {
		return state, copyErr
	} else if wasCopied == 0 {
		return state, fmt.Errorf("could not copy floor bid from %s to %s", keyBidSource, keyFloorBid) //nolint:goerr113
	}
	err = tx.Expire(ctx, keyFloorBid, expiryBidCache).Err()
	if err != nil {
		return state, err
	}

	keyFloorBidValue := r.keyFloorBidValue(submission.Slot, submission.ParentHash.String(), submission.Proposer.String())
	err = tx.Set(ctx, keyFloorBidValue, submission.Value.Dec(), expiryBidCache).Err()
	if err != nil {
		return state, err
	}

	// Execute setting the floor bid
	_, err = tx.Exec(ctx)

	// Record time needed to update floor
	nextTime = time.Now().UTC()
	state.TimeUpdateFloor = nextTime.Sub(prevTime)

	return state, err
}

func (r *RedisCache) _updateTopBid(ctx context.Context, tx redis.Pipeliner, state SaveBidAndUpdateTopBidResponse, builderBids *BuilderBids, slot uint64, parentHash, proposerPubkey string, floorValue *big.Int) (resp SaveBidAndUpdateTopBidResponse, err error) {
	if builderBids == nil {
		builderBids, err = NewBuilderBidsFromRedis(ctx, r, tx, slot, parentHash, proposerPubkey)
		if err != nil {
			return state, err
		}
	}

	if len(builderBids.bidValues) == 0 {
		return state, nil
	}

	// Load floor value (if not passed in already)
	if floorValue == nil {
		floorValue, err = r.GetFloorBidValue(ctx, tx, slot, parentHash, proposerPubkey)
		if err != nil {
			return state, err
		}
	}

	topBidBuilder := ""
	topBidBuilder, state.TopBidValue = builderBids.getTopBid()
	keyBidSource := r.keyLatestBidByBuilder(slot, parentHash, proposerPubkey, topBidBuilder)

	// If floor value is higher than this bid, use floor bid instead
	if floorValue.Cmp(state.TopBidValue) == 1 {
		state.TopBidValue = floorValue
		keyBidSource = r.keyFloorBid(slot, parentHash, proposerPubkey)
	}

	// Copy winning bid to top bid cache
	keyTopBid := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	c := tx.Copy(context.Background(), keyBidSource, keyTopBid, 0, true)
	_, err = tx.Exec(ctx)
	if err != nil {
		return state, err
	}
	wasCopied, err := c.Result()
	if err != nil {
		return state, err
	} else if wasCopied == 0 {
		return state, fmt.Errorf("could not copy top bid from %s to %s", keyBidSource, keyTopBid) //nolint:goerr113
	}
	err = tx.Expire(context.Background(), keyTopBid, expiryBidCache).Err()
	if err != nil {
		return state, err
	}

	state.WasTopBidUpdated = state.PrevTopBidValue == nil || state.PrevTopBidValue.Cmp(state.TopBidValue) != 0

	// 6. Finally, update the global top bid value
	keyTopBidValue := r.keyTopBidValue(slot, parentHash, proposerPubkey)
	err = tx.Set(context.Background(), keyTopBidValue, state.TopBidValue.String(), expiryBidCache).Err()
	if err != nil {
		return state, err
	}

	_, err = tx.Exec(ctx)
	return state, err
}

// GetTopBidValue gets the top bid value for a given slot+parent+proposer combination
func (r *RedisCache) GetTopBidValue(ctx context.Context, tx redis.Pipeliner, slot uint64, parentHash, proposerPubkey string) (topBidValue *big.Int, err error) {
	keyTopBidValue := r.keyTopBidValue(slot, parentHash, proposerPubkey)
	c := tx.Get(ctx, keyTopBidValue)
	_, err = tx.Exec(ctx)
	if errors.Is(err, redis.Nil) {
		return big.NewInt(0), nil
	} else if err != nil {
		return nil, err
	}

	topBidValueStr, err := c.Result()
	if err != nil {
		return nil, err
	}
	topBidValue = new(big.Int)
	topBidValue, ok := topBidValue.SetString(topBidValueStr, 10)
	if !ok {
		return nil, fmt.Errorf("could not set top bid value from %s", topBidValueStr) //nolint:goerr113
	}
	return topBidValue, nil
}

// GetBuilderLatestValue gets the latest bid value for a given slot+parent+proposer combination for a specific builder pubkey.
func (r *RedisCache) GetBuilderLatestValue(slot uint64, parentHash, proposerPubkey, builderPubkey string) (topBidValue *big.Int, err error) {
	keyLatestValue := r.keyBlockBuilderLatestBidsValue(slot, parentHash, proposerPubkey)
	topBidValueStr, err := r.client.HGet(context.Background(), keyLatestValue, builderPubkey).Result()
	if errors.Is(err, redis.Nil) {
		return big.NewInt(0), nil
	} else if err != nil {
		return nil, err
	}
	topBidValue = new(big.Int)
	topBidValue, ok := topBidValue.SetString(topBidValueStr, 10)
	if !ok {
		return nil, fmt.Errorf("could not set top bid value from %s", topBidValueStr) //nolint:goerr113
	}
	return topBidValue, nil
}

// DelBuilderBid removes a builders most recent bid
func (r *RedisCache) DelBuilderBid(ctx context.Context, tx redis.Pipeliner, slot uint64, parentHash, proposerPubkey, builderPubkey string) (err error) {
	// delete the value
	keyLatestValue := r.keyBlockBuilderLatestBidsValue(slot, parentHash, proposerPubkey)
	err = r.client.HDel(ctx, keyLatestValue, builderPubkey).Err()
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	// delete the time
	keyLatestBidsTime := r.keyBlockBuilderLatestBidsTime(slot, parentHash, proposerPubkey)
	err = r.client.HDel(ctx, keyLatestBidsTime, builderPubkey).Err()
	if err != nil {
		return err
	}

	// update bids now to compute current top bid
	state := SaveBidAndUpdateTopBidResponse{} //nolint:exhaustruct
	_, err = r._updateTopBid(ctx, tx, state, nil, slot, parentHash, proposerPubkey, nil)
	return err
}

// GetFloorBidValue returns the value of the highest non-cancellable bid
func (r *RedisCache) GetFloorBidValue(ctx context.Context, tx redis.Pipeliner, slot uint64, parentHash, proposerPubkey string) (floorValue *big.Int, err error) {
	keyFloorBidValue := r.keyFloorBidValue(slot, parentHash, proposerPubkey)
	c := tx.Get(ctx, keyFloorBidValue)

	_, err = tx.Exec(ctx)
	if errors.Is(err, redis.Nil) {
		return big.NewInt(0), nil
	} else if err != nil {
		return nil, err
	}

	topBidValueStr, err := c.Result()
	if err != nil {
		return nil, err
	}
	floorValue = new(big.Int)
	floorValue.SetString(topBidValueStr, 10)
	return floorValue, nil
}

func (r *RedisCache) NewPipeline() redis.Pipeliner { //nolint:ireturn,nolintlint
	return r.client.Pipeline()
}

func (r *RedisCache) NewTxPipeline() redis.Pipeliner { //nolint:ireturn
	return r.client.TxPipeline()
}
