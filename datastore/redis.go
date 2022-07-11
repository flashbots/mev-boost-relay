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

func (r *RedisDatastore) GetObj(key string, obj any) (err error) {
	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), &obj)
}

func (r *RedisDatastore) SetObj(key string, value any, expiration time.Duration) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(context.Background(), key, marshalledValue, expiration).Err()
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

func PubkeyHexToLowerStr(pk types.PubkeyHex) string {
	return strings.ToLower(string(pk))
}

func (r *RedisDatastore) GetKnownValidators() (map[types.PubkeyHex]bool, error) {
	validators := make(map[types.PubkeyHex]bool)
	keys, err := r.client.HKeys(context.Background(), redisSetKeyValidatorKnown).Result()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		validators[types.PubkeyHex(key)] = true
	}
	return validators, nil
}

func (r *RedisDatastore) SetKnownValidator(pubkeyHex types.PubkeyHex) error {
	return r.client.HSet(context.Background(), redisSetKeyValidatorKnown, PubkeyHexToLowerStr(pubkeyHex), "1").Err()
}

func (r *RedisDatastore) SetKnownValidators(pubkeys []types.PubkeyHex) error {
	pkMap := make(map[string]string)
	for _, key := range pubkeys {
		pkMap[PubkeyHexToLowerStr(key)] = "1"
	}
	return r.client.HSet(context.Background(), redisSetKeyValidatorKnown, pkMap).Err()
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

func (r *RedisDatastore) GetValidatorRegistrationTimestamp(proposerPubkey types.PubkeyHex) (uint64, error) {
	timestamp, err := r.client.Get(context.Background(), RedisKeyValidatorRegistrationTimestamp(proposerPubkey)).Uint64()
	if err == redis.Nil {
		return 0, nil
	}
	return timestamp, err
}

func (r *RedisDatastore) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	err := r.client.Set(context.Background(), RedisKeyValidatorRegistrationTimestamp(entry.Message.Pubkey.PubkeyHex()), entry.Message.Timestamp, expirationTimeValidatorRegistration).Err()
	if err != nil {
		return err
	}

	err = r.SetObj(RedisKeyValidatorRegistration(entry.Message.Pubkey.PubkeyHex()), entry, expirationTimeValidatorRegistration)
	return err
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
