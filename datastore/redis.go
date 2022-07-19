package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
)

var redisPrefix = "boost-relay"

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

	keyKnownValidators                string
	keyValidatorRegistration          string
	keyValidatorRegistrationTimestamp string
}

func NewRedisCache(redisURI string, prefix string) (*RedisCache, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisCache{
		client: client,

		keyKnownValidators:                fmt.Sprintf("%s/%s:known-validators", redisPrefix, prefix),
		keyValidatorRegistration:          fmt.Sprintf("%s/%s:validators-registration-timestamp", redisPrefix, prefix),
		keyValidatorRegistrationTimestamp: fmt.Sprintf("%s/%s:validators-registration", redisPrefix, prefix),
	}, nil
}

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func (r *RedisCache) GetKnownValidators() (map[types.PubkeyHex]uint64, error) {
	validators := make(map[types.PubkeyHex]uint64)
	entries, err := r.client.HGetAll(context.Background(), r.keyKnownValidators).Result()
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
	return r.client.HSet(context.Background(), r.keyKnownValidators, PubkeyHexToLowerStr(pubkeyHex), proposerIndex).Err()
}

func (r *RedisCache) GetValidatorRegistration(proposerPubkey types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	registration := new(types.SignedValidatorRegistration)
	value, err := r.client.HGet(context.Background(), r.keyValidatorRegistration, strings.ToLower(proposerPubkey.String())).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(value), registration)
	return registration, err
}

func (r *RedisCache) GetValidatorRegistrationTimestamp(proposerPubkey types.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.HGet(context.Background(), r.keyValidatorRegistrationTimestamp, strings.ToLower(proposerPubkey.String())).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisCache) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	err := r.client.HSet(context.Background(), r.keyValidatorRegistrationTimestamp, strings.ToLower(entry.Message.Pubkey.PubkeyHex().String()), entry.Message.Timestamp).Err()
	if err != nil {
		return err
	}

	marshalledValue, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	err = r.client.HSet(context.Background(), r.keyValidatorRegistration, strings.ToLower(entry.Message.Pubkey.PubkeyHex().String()), marshalledValue).Err()
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

func (r *RedisCache) NumRegisteredValidators() (int64, error) {
	return r.client.HLen(context.Background(), r.keyValidatorRegistrationTimestamp).Result()
}
