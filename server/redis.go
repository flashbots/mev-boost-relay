package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	RedisPrefix        = "boost-relay:"
	RedisPrefixKnownValidator = RedisPrefix + "known-validator:"

	defaultRedisPassword  = ""
	defaultRedisHost      = "redis-boost-relay"
	defaultRedisPort      = "6379"
	defaultExpirationTime = 24 * time.Hour
)

type RedisService struct {
	client *redis.Client
	log    *logrus.Entry
}

func RedisKeyKnownValidator(pubKey string) string {
	return RedisPrefixKnownValidator + strings.ToLower(pubKey)
}

func (r *RedisService) GetValidatorRegistration(proposerPubkey types.PublicKey) *types.SignedValidatorRegistration {
	var registration *types.SignedValidatorRegistration
	// Check if the registration is in the cache
	r.GetFromCache(RedisKeyKnownValidator(proposerPubkey.String()), &registration)
	if registration != nil {
		return registration
	}
	return nil
}

func (r *RedisService) SaveValidatorRegistration(entry types.SignedValidatorRegistration) {
	if !r.SetInCache(RedisKeyKnownValidator(entry.Message.Pubkey.String()), entry) {
		r.log.Error("error saving validator registration to cache")
	}
}

func (r *RedisService) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) {
	for _, entry := range entries {
		r.SaveValidatorRegistration(entry)
	}
}

func (r *RedisService) GetFromCache(key string, obj any) any {
	log := r.log.WithField("method", "GetFromCache").WithField("key", key)
	var err error

	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		if err != redis.Nil {
			log.WithError(err).Error("error getting from cache")
		}
		return nil
	}

	err = json.Unmarshal([]byte(value), &obj)
	if err != nil {
		log.WithError(err).Error("error unmarshalling from cache")
		return nil
	}
	return obj
}

func (r *RedisService) SetInCache(key string, value any) bool {
	log := r.log.WithField("method", "SetInCache").WithField("key", key)
	var err error

	marshalledValue, err := json.Marshal(value)
	if err != nil {
		log.WithError(err).Error("error marshalling value")
		return false
	}

	err = r.client.Set(context.Background(), key, marshalledValue, defaultExpirationTime).Err()
	if err != nil {
		log.WithError(err).Error("error setting in cache")
		return false
	}
	return true
}

func NewRedisService(log *logrus.Entry) (Datastore, error) {
	client, err := connectRedis()
	if err != nil {
		return nil, err
	}

	return &RedisService{
		client: client,
		log:    log.WithField("service", "redis"),
	}, nil
}

func getRedisEndpoint() string {
	redisHost := common.GetEnv("REDIS_HOST", defaultRedisHost)
	redisPort := common.GetEnv("REDIS_PORT", defaultRedisPort)
	return fmt.Sprintf("%s:%s", redisHost, redisPort)
}

func connectRedis() (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     getRedisEndpoint(),
		Password: common.GetEnv("REDIS_PASSWORD", defaultRedisPassword),
		DB:       0,
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		// unable to connect to redis
		return nil, err
	}
	return redisClient, nil
}
