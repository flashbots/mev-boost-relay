package datastore

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
)

var (
	redisPrefix                      = "boost-relay:"
	redisPrefixValidatorKnown        = redisPrefix + "validator-known:"
	redisPrefixValidatorRegistration = redisPrefix + "validator-registration:"

	expirationTimeValidatorRegistration = time.Duration(0) // never expires
	expirationTimeKnownValidators       = time.Hour * 24 * 7
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

type RedisDatastore struct {
	client *redis.Client
}

func NewRedisDatastore(redisURI string) (*RedisDatastore, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisDatastore{client: client}, nil
}

func RedisKeyKnownValidator(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorKnown + strings.ToLower(string(pubKey))
}

func RedisKeyValidatorRegistration(pubKey types.PubkeyHex) string {
	return redisPrefixValidatorRegistration + strings.ToLower(string(pubKey))
}

func (r *RedisDatastore) GetObj(key string, obj any) (err error) {
	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), &obj)
}

func (r *RedisDatastore) SetObj(key string, value any) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(context.Background(), key, marshalledValue, expirationTimeValidatorRegistration).Err()
}

// func (r *RedisDatastore) IsKnownValidator(pubkeyHex types.PubkeyHex) (bool, error) {
// 	_, err := r.client.Get(context.Background(), RedisKeyKnownValidator(pubkeyHex)).Result()
// 	if err == redis.Nil {
// 		return false, nil
// 	} else if err != nil {
// 		return false, err
// 	}
// 	return true, nil
// }

func (r *RedisDatastore) GetKnownValidators() (map[types.PubkeyHex]bool, error) {
	validators := make(map[types.PubkeyHex]bool)
	keys, err := r.client.Keys(context.Background(), redisPrefixValidatorKnown+"*").Result()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		pubkey := strings.TrimPrefix(key, redisPrefixValidatorKnown)
		validators[types.PubkeyHex(pubkey)] = true
	}
	return validators, nil
}

func (r *RedisDatastore) SetKnownValidator(pubkeyHex types.PubkeyHex) error {
	return r.client.Set(context.Background(), RedisKeyKnownValidator(pubkeyHex), true, expirationTimeKnownValidators).Err()
}

// // SetKnownValidators is a batch version of SetKnownValidator (much faster)
// func (r *RedisDatastore) SetKnownValidators(knownValidators map[types.PubkeyHex]beaconclient.ValidatorResponseEntry) (err error) {
// 	m := make(map[string]int)
// 	for pubkeyHex := range knownValidators {
// 		m[RedisKeyKnownValidator(pubkeyHex)] = 1
// 	}
// 	fmt.Println("xxx", len(m))
// 	err = r.client.MSet(context.Background(), m).Err()
// 	if err != nil {
// 		return err
// 	}
// 	for pubkeyHex := range knownValidators {
// 		err = r.client.Expire(context.Background(), RedisKeyKnownValidator(pubkeyHex), expirationTimeKnownValidators).Err()
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

func (r *RedisDatastore) GetValidatorRegistration(proposerPubkey types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	registration := new(types.SignedValidatorRegistration)
	err := r.GetObj(RedisKeyValidatorRegistration(proposerPubkey), &registration)
	if err == redis.Nil {
		return nil, nil
	}
	return registration, err
}

func (r *RedisDatastore) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	return r.SetObj(RedisKeyValidatorRegistration(entry.Message.Pubkey.PubkeyHex()), entry)
}

func (r *RedisDatastore) SetValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	for _, entry := range entries {
		err := r.SetValidatorRegistration(entry)
		if err != nil {
			return err
		}
	}
	return nil
}
