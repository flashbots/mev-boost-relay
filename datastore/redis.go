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

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix = "boost-relay"

	expiryBidCache = 45 * time.Second

	activeValidatorsHours  = cli.GetEnvInt("ACTIVE_VALIDATOR_HOURS", 3)
	expiryActiveValidators = time.Duration(activeValidatorsHours) * time.Hour // careful with this setting - for each hour a hash set is created with each active proposer as field. for a lot of hours this can take a lot of space in redis.

	RedisConfigFieldPubkey                  = "pubkey"
	RedisStatsFieldLatestSlot               = "latest-slot"
	RedisStatsFieldValidatorsTotal          = "validators-total"
	RedisStatsFieldSlotLastPayloadDelivered = "slot-last-payload-delivered"

	ErrFailedUpdatingTopBidNoBids = errors.New("failed to update top bid because no bids were found")
)

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
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
	client *redis.Client

	// prefixes (keys generated with a function)
	prefixGetHeaderResponse           string
	prefixGetPayloadResponse          string
	prefixBidTrace                    string
	prefixActiveValidators            string
	prefixBlockBuilderLatestBids      string // latest bid for a given slot
	prefixBlockBuilderLatestBidsValue string // value of latest bid for a given slot
	prefixBlockBuilderLatestBidsTime  string // when the request was received, to avoid older requests overwriting newer ones after a slot validation

	// keys
	keyKnownValidators                string
	keyValidatorRegistrationTimestamp string

	keyRelayConfig    string
	keyStats          string
	keyProposerDuties string
}

func NewRedisCache(redisURI, prefix string) (*RedisCache, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisCache{
		client: client,

		prefixGetHeaderResponse:  fmt.Sprintf("%s/%s:cache-gethead-response", redisPrefix, prefix),
		prefixGetPayloadResponse: fmt.Sprintf("%s/%s:cache-getpayload-response", redisPrefix, prefix),
		prefixBidTrace:           fmt.Sprintf("%s/%s:cache-bid-trace", redisPrefix, prefix),
		prefixActiveValidators:   fmt.Sprintf("%s/%s:active-validators", redisPrefix, prefix), // one entry per hour

		prefixBlockBuilderLatestBids:      fmt.Sprintf("%s/%s:block-builder-latest-bid", redisPrefix, prefix),       // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsValue: fmt.Sprintf("%s/%s:block-builder-latest-bid-value", redisPrefix, prefix), // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field
		prefixBlockBuilderLatestBidsTime:  fmt.Sprintf("%s/%s:block-builder-latest-bid-time", redisPrefix, prefix),  // hashmap for slot+parentHash+proposerPubkey with builderPubkey as field

		keyKnownValidators:                fmt.Sprintf("%s/%s:known-validators", redisPrefix, prefix),
		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validator-registration-timestamp", redisPrefix, prefix),
		keyRelayConfig:                    fmt.Sprintf("%s/%s:relay-config", redisPrefix, prefix),

		keyStats:          fmt.Sprintf("%s/%s:stats", redisPrefix, prefix),
		keyProposerDuties: fmt.Sprintf("%s/%s:proposer-duties", redisPrefix, prefix),
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

// keyBlockBuilderLatestBid returns the hashmap key for the getHeader response the latest bid by a specific builder
func (r *RedisCache) keyBlockBuilderLatestBids(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBlockBuilderLatestBids, slot, parentHash, proposerPubkey)
}

// keyBlockBuilderLatestBidValue returns the hashmap key for the value of the latest bid by a specific builder
func (r *RedisCache) keyBlockBuilderLatestBidsValue(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBlockBuilderLatestBidsValue, slot, parentHash, proposerPubkey)
}

// keyBlockBuilderLatestBidValue returns the hashmap key for the time of the latest bid by a specific builder
func (r *RedisCache) keyBlockBuilderLatestBidsTime(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixBlockBuilderLatestBidsTime, slot, parentHash, proposerPubkey)
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

func (r *RedisCache) GetKnownValidators() (map[types.PubkeyHex]uint64, error) {
	validators := make(map[types.PubkeyHex]uint64)
	entries, err := r.client.HGetAll(context.Background(), r.keyKnownValidators).Result()
	if err != nil {
		return nil, err
	}
	for pubkey, proposerIndexStr := range entries {
		proposerIndex, err := strconv.ParseUint(proposerIndexStr, 10, 64)
		if err == nil {
			validators[types.PubkeyHex(pubkey)] = proposerIndex
		}
	}
	return validators, nil
}

func (r *RedisCache) SetKnownValidator(pubkeyHex types.PubkeyHex, proposerIndex uint64) error {
	return r.client.HSet(context.Background(), r.keyKnownValidators, PubkeyHexToLowerStr(pubkeyHex), proposerIndex).Err()
}

func (r *RedisCache) SetKnownValidatorNX(pubkeyHex types.PubkeyHex, proposerIndex uint64) error {
	return r.client.HSetNX(context.Background(), r.keyKnownValidators, PubkeyHexToLowerStr(pubkeyHex), proposerIndex).Err()
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(proposerPubkey types.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.HGet(context.Background(), r.keyValidatorRegistrationTimestamp, strings.ToLower(proposerPubkey.String())).Uint64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistrationTimestampIfNewer(proposerPubkey types.PubkeyHex, timestamp uint64) error {
	knownTimestamp, err := r.GetValidatorRegistrationTimestamp(proposerPubkey)
	if err != nil {
		return err
	}
	if knownTimestamp >= timestamp {
		return nil
	}
	return r.SetValidatorRegistrationTimestamp(proposerPubkey, timestamp)
}

func (r *RedisCache) SetValidatorRegistrationTimestamp(proposerPubkey types.PubkeyHex, timestamp uint64) error {
	return r.client.HSet(context.Background(), r.keyValidatorRegistrationTimestamp, proposerPubkey.String(), timestamp).Err()
}

func (r *RedisCache) SetActiveValidator(pubkeyHex types.PubkeyHex) error {
	key := r.keyActiveValidators(time.Now())
	err := r.client.HSet(context.Background(), key, PubkeyHexToLowerStr(pubkeyHex), "1").Err()
	if err != nil {
		return err
	}

	// set expiry
	return r.client.Expire(context.Background(), key, expiryActiveValidators).Err()
}

func (r *RedisCache) GetActiveValidators() (map[types.PubkeyHex]bool, error) {
	hours := activeValidatorsHours
	now := time.Now()
	validators := make(map[types.PubkeyHex]bool)
	for i := 0; i < hours; i++ {
		key := r.keyActiveValidators(now.Add(time.Duration(-i) * time.Hour))
		entries, err := r.client.HGetAll(context.Background(), key).Result()
		if err != nil {
			return nil, err
		}
		for pubkey := range entries {
			validators[types.PubkeyHex(pubkey)] = true
		}
	}

	return validators, nil
}

func (r *RedisCache) SetStats(field string, value any) (err error) {
	return r.client.HSet(context.Background(), r.keyStats, field, value).Err()
}

func (r *RedisCache) GetStats(field string) (value string, err error) {
	return r.client.HGet(context.Background(), r.keyStats, field).Result()
}

func (r *RedisCache) SetProposerDuties(proposerDuties []types.BuilderGetValidatorsResponseEntry) (err error) {
	return r.SetObj(r.keyProposerDuties, proposerDuties, 0)
}

func (r *RedisCache) GetProposerDuties() (proposerDuties []types.BuilderGetValidatorsResponseEntry, err error) {
	proposerDuties = make([]types.BuilderGetValidatorsResponseEntry, 0)
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

func (r *RedisCache) GetBestBid(slot uint64, parentHash, proposerPubkey string) (*types.GetHeaderResponse, error) {
	key := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	resp := new(types.GetHeaderResponse)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SaveExecutionPayload(slot uint64, proposerPubkey, blockHash string, resp *types.GetPayloadResponse) (err error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, blockHash)
	return r.SetObj(key, resp, expiryBidCache)
}

func (r *RedisCache) GetExecutionPayload(slot uint64, proposerPubkey, blockHash string) (*types.GetPayloadResponse, error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, blockHash)
	resp := new(types.GetPayloadResponse)
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

// SaveLatestBuilderBid saves the latest bid by a specific builder
func (r *RedisCache) SaveLatestBuilderBid(slot uint64, builderPubkey, parentHash, proposerPubkey string, receivedAt time.Time, headerResp *types.GetHeaderResponse) (err error) {
	keyLatestBids := r.keyBlockBuilderLatestBids(slot, parentHash, proposerPubkey)
	err = r.HSetObj(keyLatestBids, builderPubkey, headerResp, expiryBidCache)
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
	err = r.client.HSet(context.Background(), keyLatestBidsValue, builderPubkey, headerResp.Data.Message.Value.String()).Err()
	if err != nil {
		return err
	}
	return r.client.Expire(context.Background(), keyLatestBidsValue, expiryBidCache).Err()
}

func (r *RedisCache) UpdateTopBid(slot uint64, parentHash, proposerPubkey string) (err error) {
	// Get all builder's latest submission values
	keyBidValues := r.keyBlockBuilderLatestBidsValue(slot, parentHash, proposerPubkey)
	bidValueMap, err := r.client.HGetAll(context.Background(), keyBidValues).Result()
	if err != nil {
		return err
	}

	// Find bid with highest value among all the latest bids
	topBidValue := big.NewInt(0)
	topBidBuilderPubkey := ""
	for builderPubkey, bidValue := range bidValueMap {
		val := new(big.Int)
		val.SetString(bidValue, 10)
		if val.Cmp(topBidValue) > 0 {
			topBidValue = val
			topBidBuilderPubkey = builderPubkey
		}
	}

	if topBidBuilderPubkey == "" {
		return ErrFailedUpdatingTopBidNoBids
	}

	// Get the actual bid
	keyBid := r.keyBlockBuilderLatestBids(slot, parentHash, proposerPubkey)
	bidStr, err := r.client.HGet(context.Background(), keyBid, topBidBuilderPubkey).Result()
	if err != nil {
		return err
	}

	// Save the top bid
	keyTopBid := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	return r.client.Set(context.Background(), keyTopBid, bidStr, expiryBidCache).Err()
}
