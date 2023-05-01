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

	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix = "boost-relay"

	expiryBidCache = 45 * time.Second

	activeValidatorsHours  = cli.GetEnvInt("ACTIVE_VALIDATOR_HOURS", 3)
	expiryActiveValidators = time.Duration(activeValidatorsHours) * time.Hour // careful with this setting - for each hour a hash set is created with each active proposer as field. for a lot of hours this can take a lot of space in redis.

	RedisConfigFieldPubkey         = "pubkey"
	RedisStatsFieldLatestSlot      = "latest-slot"
	RedisStatsFieldValidatorsTotal = "validators-total"

	ErrFailedUpdatingTopBidNoBids = errors.New("failed to update top bid because no bids were found")
	ErrSlotAlreadyDelivered       = errors.New("payload for slot was already delivered")
)

func PubkeyHexToLowerStr(pk boostTypes.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func connectRedis(redisURI string) (*redis.Client, error) {
	// Handle both URIs and full URLs, assume unencrypted connections
	if !strings.HasPrefix(redisURI, "redis://") && !strings.HasPrefix(redisURI, "rediss://") {
		redisURI = "redis://" + redisURI
	}
	opt, err := redis.ParseURL(redisURI)
	if err != nil {
		return nil, err
	}
	redisClient := redis.NewClient(opt)
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
	prefixGetPayloadResponse          string
	prefixBidTrace                    string
	prefixActiveValidators            string
	prefixBlockBuilderLatestBids      string // latest bid for a given slot
	prefixBlockBuilderLatestBidsValue string // value of latest bid for a given slot
	prefixBlockBuilderLatestBidsTime  string // when the request was received, to avoid older requests overwriting newer ones after a slot validation
	prefixTopBidValue                 string

	// keys
	keyKnownValidators                string
	keyValidatorRegistrationTimestamp string

	keyRelayConfig        string
	keyStats              string
	keyProposerDuties     string
	keyBlockBuilderStatus string
	keyLastSlotDelivered  string
}

func NewRedisCache(prefix, redisURI, readonlyURI string) (*RedisCache, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	var roClient *redis.Client
	if readonlyURI != "" {
		roClient, err = connectRedis(readonlyURI)
		if err != nil {
			return nil, err
		}
	} else {
		roClient = client
	}

	return &RedisCache{
		client:         client,
		readonlyClient: roClient,

		prefixGetHeaderResponse:  fmt.Sprintf("%s/%s:cache-gethead-response", redisPrefix, prefix),
		prefixGetPayloadResponse: fmt.Sprintf("%s/%s:cache-getpayload-response", redisPrefix, prefix),
		prefixBidTrace:           fmt.Sprintf("%s/%s:cache-bid-trace", redisPrefix, prefix),
		prefixActiveValidators:   fmt.Sprintf("%s/%s:active-validators", redisPrefix, prefix), // one entry per hour

		prefixBlockBuilderLatestBids:      fmt.Sprintf("%s/%s:block-builder-latest-bid", redisPrefix, prefix),       // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsValue: fmt.Sprintf("%s/%s:block-builder-latest-bid-value", redisPrefix, prefix), // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsTime:  fmt.Sprintf("%s/%s:block-builder-latest-bid-time", redisPrefix, prefix),  // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixTopBidValue:                 fmt.Sprintf("%s/%s:top-bid-value", redisPrefix, prefix),                  // hashmap for slot+parentHash+proposerPubkey with top bid value as value

		keyKnownValidators:                fmt.Sprintf("%s/%s:known-validators", redisPrefix, prefix),
		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validator-registration-timestamp", redisPrefix, prefix),
		keyRelayConfig:                    fmt.Sprintf("%s/%s:relay-config", redisPrefix, prefix),

		keyStats:              fmt.Sprintf("%s/%s:stats", redisPrefix, prefix),
		keyProposerDuties:     fmt.Sprintf("%s/%s:proposer-duties", redisPrefix, prefix),
		keyBlockBuilderStatus: fmt.Sprintf("%s/%s:block-builder-status", redisPrefix, prefix),
		keyLastSlotDelivered:  fmt.Sprintf("%s/%s:last-slot-delivered", redisPrefix, prefix),
	}, nil
}

func (r *RedisCache) keyCacheGetHeaderResponse(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixGetHeaderResponse, slot, parentHash, proposerPubkey)
}

func (r *RedisCache) keyCacheGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixGetPayloadResponse, slot, proposerPubkey, blockHash)
}

func (r *RedisCache) keyCacheBidTrace(slot uint64, proposerPubkey, blockHash string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBidTrace, slot, proposerPubkey, blockHash)
}

// keyActiveValidators returns the key for the date + hour of the given time
func (r *RedisCache) keyActiveValidators(t time.Time) string {
	return fmt.Sprintf("%s:%s", r.prefixActiveValidators, t.UTC().Format("2006-01-02T15"))
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

func (r *RedisCache) GetKnownValidators() (map[uint64]boostTypes.PubkeyHex, error) {
	validators := make(map[uint64]boostTypes.PubkeyHex)
	entries, err := r.readonlyClient.HGetAll(context.Background(), r.keyKnownValidators).Result()
	if err != nil {
		return nil, err
	}
	for proposerIndexStr, pubkey := range entries {
		if strings.HasPrefix(proposerIndexStr, "0x") {
			// remove -- it's an artifact of the previous storage by pubkey
			r.client.HDel(context.Background(), r.keyKnownValidators, proposerIndexStr)
			continue
		}
		proposerIndex, err := strconv.ParseUint(proposerIndexStr, 10, 64)
		if err == nil {
			validators[proposerIndex] = boostTypes.PubkeyHex(pubkey)
		}
	}
	return validators, nil
}

func (r *RedisCache) SetKnownValidator(pubkeyHex boostTypes.PubkeyHex, proposerIndex uint64) error {
	return r.client.HSet(context.Background(), r.keyKnownValidators, proposerIndex, PubkeyHexToLowerStr(pubkeyHex)).Err()
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(proposerPubkey boostTypes.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.HGet(context.Background(), r.keyValidatorRegistrationTimestamp, strings.ToLower(proposerPubkey.String())).Uint64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistrationTimestampIfNewer(proposerPubkey boostTypes.PubkeyHex, timestamp uint64) error {
	knownTimestamp, err := r.GetValidatorRegistrationTimestamp(proposerPubkey)
	if err != nil {
		return err
	}
	if knownTimestamp >= timestamp {
		return nil
	}
	return r.SetValidatorRegistrationTimestamp(proposerPubkey, timestamp)
}

func (r *RedisCache) SetValidatorRegistrationTimestamp(proposerPubkey boostTypes.PubkeyHex, timestamp uint64) error {
	return r.client.HSet(context.Background(), r.keyValidatorRegistrationTimestamp, proposerPubkey.String(), timestamp).Err()
}

func (r *RedisCache) SetActiveValidator(pubkeyHex boostTypes.PubkeyHex) error {
	key := r.keyActiveValidators(time.Now())
	err := r.client.HSet(context.Background(), key, PubkeyHexToLowerStr(pubkeyHex), "1").Err()
	if err != nil {
		return err
	}

	// set expiry
	return r.client.Expire(context.Background(), key, expiryActiveValidators).Err()
}

func (r *RedisCache) GetActiveValidators() (map[boostTypes.PubkeyHex]bool, error) {
	hours := activeValidatorsHours
	now := time.Now()
	validators := make(map[boostTypes.PubkeyHex]bool)
	for i := 0; i < hours; i++ {
		key := r.keyActiveValidators(now.Add(time.Duration(-i) * time.Hour))
		entries, err := r.readonlyClient.HGetAll(context.Background(), key).Result()
		if err != nil {
			return nil, err
		}
		for pubkey := range entries {
			validators[boostTypes.PubkeyHex(pubkey)] = true
		}
	}

	return validators, nil
}

func (r *RedisCache) CheckAndSetLastSlotDelivered(slot uint64) (err error) {
	// More details about Redis optimistic locking:
	// - https://redis.uptrace.dev/guide/go-redis-pipelines.html#transactions
	// - https://github.com/redis/go-redis/blob/6ecbcf6c90919350c42181ce34c1cbdfbd5d1463/race_test.go#L183
	txf := func(tx *redis.Tx) error {
		lastSlotDelivered, err := tx.Get(context.Background(), r.keyLastSlotDelivered).Uint64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}

		if slot <= lastSlotDelivered {
			return ErrSlotAlreadyDelivered
		}

		_, err = tx.TxPipelined(context.Background(), func(pipe redis.Pipeliner) error {
			pipe.Set(context.Background(), r.keyLastSlotDelivered, slot, 0)
			return nil
		})

		return err
	}

	return r.client.Watch(context.Background(), txf, r.keyLastSlotDelivered)
}

func (r *RedisCache) GetLastSlotDelivered() (slot uint64, err error) {
	return r.client.Get(context.Background(), r.keyLastSlotDelivered).Uint64()
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

func (r *RedisCache) GetBestBid(slot uint64, parentHash, proposerPubkey string) (*common.GetHeaderResponse, error) {
	key := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	resp := new(common.GetHeaderResponse)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SaveExecutionPayload(slot uint64, proposerPubkey, blockHash string, resp *common.GetPayloadResponse) (err error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, blockHash)
	return r.SetObj(key, resp, expiryBidCache)
}

func (r *RedisCache) GetExecutionPayload(slot uint64, proposerPubkey, blockHash string) (*common.VersionedExecutionPayload, error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, blockHash)
	resp := new(common.VersionedExecutionPayload)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SaveBidTrace(trace *common.BidTraceV2) (err error) {
	key := r.keyCacheBidTrace(trace.Slot, trace.ProposerPubkey.String(), trace.BlockHash.String())
	return r.SetObj(key, trace, expiryBidCache)
}

func (r *RedisCache) GetBidTrace(slot uint64, proposerPubkey, blockHash string) (*common.BidTraceV2, error) {
	key := r.keyCacheBidTrace(slot, proposerPubkey, blockHash)
	resp := new(common.BidTraceV2)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) GetBuilderLatestPayloadReceivedAt(slot uint64, builderPubkey, parentHash, proposerPubkey string) (int64, error) {
	keyLatestBidsTime := r.keyBlockBuilderLatestBidsTime(slot, parentHash, proposerPubkey)
	timestamp, err := r.client.HGet(context.Background(), keyLatestBidsTime, builderPubkey).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return timestamp, err
}

// SaveBuilderBid saves the latest bid by a specific builder. TODO: use transaction to make these writes atomic
func (r *RedisCache) SaveBuilderBid(slot uint64, parentHash, proposerPubkey, builderPubkey string, receivedAt time.Time, headerResp *common.GetHeaderResponse) (err error) {
	// save the actual bid
	keyLatestBid := r.keyLatestBidByBuilder(slot, parentHash, proposerPubkey, builderPubkey)
	err = r.SetObj(keyLatestBid, headerResp, expiryBidCache)
	if err != nil {
		return err
	}

	// set the time of the request
	keyLatestBidsTime := r.keyBlockBuilderLatestBidsTime(slot, parentHash, proposerPubkey)
	err = r.client.HSet(context.Background(), keyLatestBidsTime, builderPubkey, receivedAt.UnixMilli()).Err()
	if err != nil {
		return err
	}
	err = r.client.Expire(context.Background(), keyLatestBidsTime, expiryBidCache).Err()
	if err != nil {
		return err
	}

	// set the value last, because that's iterated over when updating the best bid, and the payload has to be available
	keyLatestBidsValue := r.keyBlockBuilderLatestBidsValue(slot, parentHash, proposerPubkey)
	err = r.client.HSet(context.Background(), keyLatestBidsValue, builderPubkey, headerResp.Value().String()).Err()
	if err != nil {
		return err
	}
	return r.client.Expire(context.Background(), keyLatestBidsValue, expiryBidCache).Err()
}

type SaveBidAndUpdateTopBidResponse struct {
	WasBidSaved      bool // Whether this bid was saved
	WasTopBidUpdated bool // Whether the top bid was updated
	IsNewTopBid      bool // Whether the submitted bid became the new top bid

	TopBidValue   *big.Int
	TopBidBuilder string

	PrevTopBidValue   *big.Int
	PrevTopBidBuilder string
}

func (r *RedisCache) SaveBidAndUpdateTopBid(payload *common.BuilderSubmitBlockRequest, getPayloadResponse *common.GetPayloadResponse, getHeaderResponse *common.GetHeaderResponse, reqReceivedAt time.Time, isCancellationEnabled bool) (state SaveBidAndUpdateTopBidResponse, err error) {
	// 1. Load latest bids for a given slot+parent+proposer
	keyBidValues := r.keyBlockBuilderLatestBidsValue(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey())
	bidValueMap, err := r.client.HGetAll(context.Background(), keyBidValues).Result()
	if err != nil {
		return state, err
	}

	builderBids := NewBuilderBids(bidValueMap)
	state.PrevTopBidBuilder, state.PrevTopBidValue = builderBids.getTopBid()
	state.TopBidBuilder, state.TopBidValue = state.PrevTopBidBuilder, state.PrevTopBidValue

	// 2. Do we even need to continue / save the new payload and update the top bid?
	// - In cancellation mode: always continue to saving latest bid
	// - In non-cancellation mode: only save if current bid is higher value than this builders previous bid
	if !isCancellationEnabled {
		currentBuilderLastValue := builderBids.builderValue(payload.BuilderPubkey().String())
		if payload.Value().Cmp(currentBuilderLastValue) < 1 {
			return state, nil
		}
	}

	// Time to save things in Redis
	// 1. Save the execution payload
	err = r.SaveExecutionPayload(payload.Slot(), payload.ProposerPubkey(), payload.BlockHash(), getPayloadResponse)
	if err != nil {
		return state, err
	}

	// 2. Save this bid
	err = r.SaveBuilderBid(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey(), payload.BuilderPubkey().String(), reqReceivedAt, getHeaderResponse)
	if err != nil {
		return state, err
	}

	// 3. Update this builders latest bid in local cache
	builderBids.bidValues[payload.BuilderPubkey().String()] = payload.Value()
	state.TopBidBuilder, state.TopBidValue = builderBids.getTopBid()
	state.WasBidSaved = true

	// 4. Only proceed to update top bid in redis if it changed in local cache
	if state.TopBidValue.Cmp(state.PrevTopBidValue) == 0 {
		return state, nil
	}

	// 5. Copy winning bid to top bid cache
	keyBidSource := r.keyLatestBidByBuilder(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey(), state.TopBidBuilder)
	keyTopBid := r.keyCacheGetHeaderResponse(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey())
	wasCopied, err := r.client.Copy(context.Background(), keyBidSource, keyTopBid, 0, true).Result()
	if err != nil {
		return state, err
	} else if wasCopied == 0 {
		return state, fmt.Errorf("could not copy %s to %s", keyBidSource, keyTopBid) //nolint:goerr113
	}

	state.WasTopBidUpdated = true
	state.IsNewTopBid = payload.Value().Cmp(state.TopBidValue) == 0

	// 6. Finally, update the global top bid value
	keyTopBidValue := r.keyTopBidValue(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey())
	err = r.client.Set(context.Background(), keyTopBidValue, state.TopBidValue.String(), expiryBidCache).Err()
	return state, err
}

// GetTopBidValue gets the top bid value for a given slot+parent+proposer combination
func (r *RedisCache) GetTopBidValue(slot uint64, parentHash, proposerPubkey string) (topBidValue *big.Int, err error) {
	keyTopBidValue := r.keyTopBidValue(slot, parentHash, proposerPubkey)
	topBidValueStr, err := r.client.Get(context.Background(), keyTopBidValue).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return big.NewInt(0), nil
		}
		return nil, err
	}
	topBidValue = new(big.Int)
	topBidValue.SetString(topBidValueStr, 10)
	return topBidValue, nil
}
