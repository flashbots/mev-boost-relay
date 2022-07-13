package datastore

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix                      = "boost-relay:"
	redisSetKeyValidatorKnown        = redisPrefix + "known-validators"
	redisPrefixValidatorRegistration = redisPrefix + "validator-registration:"

	expirationTimeValidatorRegistration = time.Duration(0) // never expires
)

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
}

func NewRedisCache(redisURI string) (*RedisCache, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisCache{client: client}, nil
}

func RedisKeyValidatorRegistration(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorRegistration + strings.ToLower(string(pubKey))
}

func RedisKeyValidatorRegistrationTimestamp(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorRegistration + strings.ToLower(string(pubKey)) + "/timestamp"
}

func RedisKeyValidatorRegistrationGaslimit(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorRegistration + strings.ToLower(string(pubKey)) + "/gasLimit"
}

func RedisKeyValidatorRegistrationFeeRecipient(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorRegistration + strings.ToLower(string(pubKey)) + "/feeRecipient"
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

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func (r *RedisCache) GetKnownValidators() (map[types.PubkeyHex]uint64, error) {
	validators := make(map[types.PubkeyHex]uint64)
	entries, err := r.client.HGetAll(context.Background(), redisSetKeyValidatorKnown).Result()
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

func (r *RedisCache) SetKnownValidator(pubkeyHex types.PubkeyHex, proposerIndex uint64) error {
	return r.client.HSet(context.Background(), redisSetKeyValidatorKnown, PubkeyHexToLowerStr(pubkeyHex), proposerIndex).Err()
}

// func (r *RedisCache) SetKnownValidators(pubkeys []types.PubkeyHex) error {
// 	pkMap := make(map[string]string)
// 	for _, key := range pubkeys {
// 		pkMap[PubkeyHexToLowerStr(key)] = "1"
// 	}
// 	return r.client.HSet(context.Background(), redisSetKeyValidatorKnown, pkMap).Err()
// }

func (r *RedisCache) GetValidatorRegistration(proposerPubkey types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	registration := new(types.SignedValidatorRegistration)
	err := r.GetObj(RedisKeyValidatorRegistration(proposerPubkey), &registration)
	if err == redis.Nil {
		return nil, nil
	}
	return registration, err
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(proposerPubkey types.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.Get(context.Background(), RedisKeyValidatorRegistrationTimestamp(proposerPubkey)).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	err := r.client.Set(context.Background(), RedisKeyValidatorRegistrationTimestamp(entry.Message.Pubkey.PubkeyHex()), entry.Message.Timestamp, expirationTimeValidatorRegistration).Err()
	if err != nil {
		return err
	}

	err = r.SetObj(RedisKeyValidatorRegistration(entry.Message.Pubkey.PubkeyHex()), entry, expirationTimeValidatorRegistration)
	return err
}

func (r *RedisCache) SetValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	for _, entry := range entries {
		err := r.SetValidatorRegistration(entry)
		if err != nil {
			return err
		}
	}
	return nil
}
