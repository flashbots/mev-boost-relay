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
	expirationTimeKnownValidators       = time.Duration(0) // never expires
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

type ProposerRedisDatastore struct {
	client *redis.Client
}

func NewProposerRedisDatastore(redisURI string) (*ProposerRedisDatastore, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &ProposerRedisDatastore{client: client}, nil
}

func RedisKeyKnownValidator(pubKey string) string {
	return redisPrefixValidatorKnown + strings.ToLower(pubKey)
}

func RedisKeyValidatorRegistration(pubKey string) string {
	return redisPrefixValidatorRegistration + strings.ToLower(pubKey)
}

func (r *ProposerRedisDatastore) GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	registration := new(types.SignedValidatorRegistration)
	err := r.GetObj(RedisKeyValidatorRegistration(proposerPubkey.String()), &registration)
	if err == redis.Nil {
		return nil, nil
	}
	return registration, err
}

func (r *ProposerRedisDatastore) IsKnownValidator(pubkeyHex string) (bool, error) {
	_, err := r.client.Get(context.Background(), RedisKeyKnownValidator(pubkeyHex)).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (r *ProposerRedisDatastore) SetKnownValidator(pubkeyHex string) error {
	return r.client.Set(context.Background(), RedisKeyKnownValidator(pubkeyHex), true, expirationTimeKnownValidators).Err()
}

func (r *ProposerRedisDatastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	return r.SetObj(RedisKeyValidatorRegistration(entry.Message.Pubkey.String()), entry)
}

func (r *ProposerRedisDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	for _, entry := range entries {
		err := r.SaveValidatorRegistration(entry)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *ProposerRedisDatastore) GetObj(key string, obj any) (err error) {
	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), &obj)
}

func (r *ProposerRedisDatastore) SetObj(key string, value any) (err error) {
	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(context.Background(), key, marshalledValue, expirationTimeValidatorRegistration).Err()
}
