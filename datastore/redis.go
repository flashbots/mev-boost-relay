package datastore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix = "boost-relay"

	expiryBidCache         = 5 * time.Minute
	expiryActiveValidators = 6 * time.Hour

	RedisConfigFieldPubkey    = "pubkey"
	RedisStatsFieldLatestSlot = "latest-slot"
)

type BlockBuilderStatus string

var (
	RedisBlockBuilderStatusHighPrio    BlockBuilderStatus = "high-prio"
	RedisBlockBuilderStatusBlacklisted BlockBuilderStatus = "blacklisted"
)

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func connectRedis(redisURI string) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisURI,
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		// unable to connect to redis
		return nil, err
	}
	return redisClient, nil
}

type RedisCache struct {
	client *redis.Client

	prefixGetHeaderResponse  string
	prefixGetPayloadResponse string
	prefixActiveValidators   string

	keyKnownValidators                string
	keyValidatorRegistrationTimestamp string

	keyRelayConfig        string
	keyStats              string
	keyProposerDuties     string
	keyBlockBuilderStatus string
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
		prefixActiveValidators:   fmt.Sprintf("%s/%s:active-validators", redisPrefix, prefix), // per hour

		keyKnownValidators:                fmt.Sprintf("%s/%s:known-validators", redisPrefix, prefix),
		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validator-registration-timestamp", redisPrefix, prefix),
		keyRelayConfig:                    fmt.Sprintf("%s/%s:relay-config", redisPrefix, prefix),

		keyStats:              fmt.Sprintf("%s/%s:stats", redisPrefix, prefix),
		keyProposerDuties:     fmt.Sprintf("%s/%s:proposer-duties", redisPrefix, prefix),
		keyBlockBuilderStatus: fmt.Sprintf("%s/%s:block-builder-status", redisPrefix, prefix),
	}, nil
}

func (r *RedisCache) keyCacheGetHeaderResponse(slot uint64, parentHash, proposerPubkey string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixGetHeaderResponse, slot, parentHash, proposerPubkey)
}

func (r *RedisCache) keyCacheGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) string {
	return fmt.Sprintf("%s:%d_%s_%s", r.prefixGetPayloadResponse, slot, proposerPubkey, blockHash)
}

// keyActiveValidators returns the key for the date + hour of the given time
func (r *RedisCache) keyActiveValidators(t time.Time) string {
	return fmt.Sprintf("%s:%s", r.prefixActiveValidators, t.UTC().Format("2006-01-02T15"))
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

func (r *RedisCache) NumRegisteredValidators() (int64, error) {
	return r.client.HLen(context.Background(), r.keyValidatorRegistrationTimestamp).Result()
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

func (r *RedisCache) NumActiveValidators() (uint64, error) {
	hours := int(expiryActiveValidators.Hours())
	now := time.Now()
	numActiveValidators := uint64(0)
	for i := 0; i < hours; i++ {
		key := r.keyActiveValidators(now.Add(time.Duration(-i) * time.Hour))
		entries, err := r.client.HLen(context.Background(), key).Result()
		if err != nil {
			return 0, err
		}
		numActiveValidators += uint64(entries)
	}
	return numActiveValidators, nil
}

func (r *RedisCache) GetActiveValidators() (map[types.PubkeyHex]bool, error) {
	hours := int(expiryActiveValidators.Hours())
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

func (r *RedisCache) SaveGetHeaderResponse(slot uint64, parentHash, proposerPubkey string, headerResp *types.GetHeaderResponse) (err error) {
	key := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	return r.SetObj(key, headerResp, expiryBidCache)
}

func (r *RedisCache) GetGetHeaderResponse(slot uint64, parentHash, proposerPubkey string) (*types.GetHeaderResponse, error) {
	key := r.keyCacheGetHeaderResponse(slot, parentHash, proposerPubkey)
	resp := new(types.GetHeaderResponse)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SaveGetPayloadResponse(slot uint64, proposerPubkey string, resp *types.GetPayloadResponse) (err error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, resp.Data.BlockHash.String())
	return r.SetObj(key, resp, expiryBidCache)
}

func (r *RedisCache) GetGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) (*types.GetPayloadResponse, error) {
	key := r.keyCacheGetPayloadResponse(slot, proposerPubkey, blockHash)
	resp := new(types.GetPayloadResponse)
	err := r.GetObj(key, resp)
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return resp, err
}

func (r *RedisCache) SetBlockBuilderStatus(builderPubkey string, status BlockBuilderStatus) (err error) {
	return r.client.HSet(context.Background(), r.keyBlockBuilderStatus, builderPubkey, string(status)).Err()
}

func (r *RedisCache) GetBlockBuilderStatus(builderPubkey string) (isHighPrio, isBlacklisted bool, err error) {
	res, err := r.client.HGet(context.Background(), r.keyBlockBuilderStatus, builderPubkey).Result()
	if errors.Is(err, redis.Nil) {
		return false, false, nil
	}
	isHighPrio = BlockBuilderStatus(res) == RedisBlockBuilderStatusHighPrio
	isBlacklisted = BlockBuilderStatus(res) == RedisBlockBuilderStatusBlacklisted
	return isHighPrio, isBlacklisted, err
}
