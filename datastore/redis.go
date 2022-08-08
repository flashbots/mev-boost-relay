package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix = "boost-relay"

	FieldPubkey = "pubkey"
)

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func connectRedis(ctx context.Context, redisURI string) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisURI,
	})
	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		// unable to connect to redis
		return nil, err
	}
	return redisClient, nil
}

type RedisCache struct {
	client *redis.Client

	prefixEpochSummary string
	prefixSlotSummary  string

	keyKnownValidators                string
	keyValidatorRegistration          string
	keyValidatorRegistrationTimestamp string
	// keySlotPayloadDelivered           string
	keyRelayConfig string

	keyStats          string
	keyProposerDuties string
}

func NewRedisCache(ctx context.Context, redisURI string, prefix string) (*RedisCache, error) {
	client, err := connectRedis(ctx, redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisCache{
		client: client,

		prefixEpochSummary: fmt.Sprintf("%s/%s:epoch-summary", redisPrefix, prefix),
		prefixSlotSummary:  fmt.Sprintf("%s/%s:slot-summary", redisPrefix, prefix),

		keyKnownValidators:                fmt.Sprintf("%s/%s:known-validators", redisPrefix, prefix),
		keyValidatorRegistration:          fmt.Sprintf("%s/%s:validators-registration-timestamp", redisPrefix, prefix),
		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validators-registration", redisPrefix, prefix),
		// keySlotPayloadDelivered:           fmt.Sprintf("%s/%s:payload-delivered", redisPrefix, prefix),
		keyRelayConfig: fmt.Sprintf("%s/%s:relay-config", redisPrefix, prefix),

		keyStats:          fmt.Sprintf("%s/%s:stats", redisPrefix, prefix),
		keyProposerDuties: fmt.Sprintf("%s/%s:proposer-duties", redisPrefix, prefix),
	}, nil
}

func (r *RedisCache) keyEpochSummary(epoch uint64) string {
	return fmt.Sprintf("%s:%d", r.prefixEpochSummary, epoch)
}

func (r *RedisCache) keySlotSummary(slot uint64) string {
	return fmt.Sprintf("%s:%d", r.prefixSlotSummary, slot)
}

func (r *RedisCache) GetObj(ctx context.Context, key string, obj any) (err error) {
	value, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), &obj)
}

func (r *RedisCache) SetObj(ctx context.Context, key string, value any, expiration time.Duration) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, marshalledValue, expiration).Err()
}

func (r *RedisCache) GetKnownValidators(ctx context.Context) (map[types.PubkeyHex]uint64, error) {
	validators := make(map[types.PubkeyHex]uint64)
	entries, err := r.client.HGetAll(ctx, r.keyKnownValidators).Result()
	if err != nil {
		return nil, err
	}
	for pubkey, proposerIndexStr := range entries {
		proposerIndex, err := strconv.ParseUint(proposerIndexStr, 10, 64)
		// TODO: log on error
		if err == nil {
			validators[types.PubkeyHex(pubkey)] = proposerIndex
		}
	}
	return validators, nil
}

func (r *RedisCache) SetKnownValidator(ctx context.Context, pubkeyHex types.PubkeyHex, proposerIndex uint64) error {
	return r.client.HSet(ctx, r.keyKnownValidators, PubkeyHexToLowerStr(pubkeyHex), proposerIndex).Err()
}

func (r *RedisCache) GetValidatorRegistration(ctx context.Context, proposerPubkey types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	registration := new(types.SignedValidatorRegistration)
	value, err := r.client.HGet(ctx, r.keyValidatorRegistration, strings.ToLower(proposerPubkey.String())).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(value), registration)
	return registration, err
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(ctx context.Context, proposerPubkey types.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.HGet(ctx, r.keyValidatorRegistrationTimestamp, strings.ToLower(proposerPubkey.String())).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistration(ctx context.Context, entry types.SignedValidatorRegistration) error {
	err := r.client.HSet(ctx, r.keyValidatorRegistrationTimestamp, strings.ToLower(entry.Message.Pubkey.PubkeyHex().String()), entry.Message.Timestamp).Err()
	if err != nil {
		return err
	}

	marshalledValue, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	err = r.client.HSet(ctx, r.keyValidatorRegistration, strings.ToLower(entry.Message.Pubkey.PubkeyHex().String()), marshalledValue).Err()
	return err
}

func (r *RedisCache) SetValidatorRegistrations(ctx context.Context, entries []types.SignedValidatorRegistration) error {
	for _, entry := range entries {
		err := r.SetValidatorRegistration(ctx, entry)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RedisCache) NumRegisteredValidators(ctx context.Context) (int64, error) {
	return r.client.HLen(ctx, r.keyValidatorRegistrationTimestamp).Result()
}

func (r *RedisCache) IncEpochSummaryVal(ctx context.Context, epoch uint64, field string, value int64) (newVal int64, err error) {
	return r.client.HIncrBy(ctx, r.keyEpochSummary(epoch), field, value).Result()
}

func (r *RedisCache) SetEpochSummaryVal(ctx context.Context, epoch uint64, field string, value int64) (err error) {
	return r.client.HSet(ctx, r.keyEpochSummary(epoch), field, value).Err()
}

func (r *RedisCache) SetNXEpochSummaryVal(ctx context.Context, epoch uint64, field string, value int64) (err error) {
	return r.client.HSetNX(ctx, r.keyEpochSummary(epoch), field, value).Err()
}

func (r *RedisCache) GetEpochSummary(ctx context.Context, epoch uint64) (ret map[string]string, err error) {
	return r.client.HGetAll(ctx, r.keyEpochSummary(epoch)).Result()
}

// func (r *RedisCache) SetSlotPayloadDelivered(ctx context.Context, slot uint64, proposerPubkey, blockhash string) (err error) {
// 	return r.client.HSet(ctx, r.keySlotPayloadDelivered, slot, proposerPubkey+"_"+blockhash).Err()
// }

func (r *RedisCache) IncSlotSummaryVal(ctx context.Context, slot uint64, field string, value int64) (newVal int64, err error) {
	return r.client.HIncrBy(ctx, r.keySlotSummary(slot), field, value).Result()
}

func (r *RedisCache) SetSlotSummaryVal(ctx context.Context, slot uint64, field string, value int64) (err error) {
	return r.client.HSet(ctx, r.keySlotSummary(slot), field, value).Err()
}

func (r *RedisCache) SetNXSlotSummaryVal(ctx context.Context, slot uint64, field string, value int64) (err error) {
	return r.client.HSetNX(ctx, r.keySlotSummary(slot), field, value).Err()
}

func (r *RedisCache) SetStats(ctx context.Context, field string, value string) (err error) {
	return r.client.HSet(ctx, r.keyStats, field, value).Err()
}

func (r *RedisCache) SetProposerDuties(ctx context.Context, proposerDuties []types.BuilderGetValidatorsResponseEntry) (err error) {
	return r.SetObj(ctx, r.keyProposerDuties, proposerDuties, 0)
}

func (r *RedisCache) GetProposerDuties(ctx context.Context) (proposerDuties []types.BuilderGetValidatorsResponseEntry, err error) {
	proposerDuties = make([]types.BuilderGetValidatorsResponseEntry, 0)
	err = r.GetObj(ctx, r.keyProposerDuties, &proposerDuties)
	return proposerDuties, err
}

func (r *RedisCache) SetRelayConfig(ctx context.Context, field string, value string) (err error) {
	return r.client.HSet(ctx, r.keyRelayConfig, field, value).Err()
}

func (r *RedisCache) GetRelayConfig(ctx context.Context, field string) (string, error) {
	res, err := r.client.HGet(ctx, r.keyRelayConfig, field).Result()
	if err == redis.Nil {
		return res, nil
	}
	return res, err
}
