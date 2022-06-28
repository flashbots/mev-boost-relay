package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/go-redis/redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	RedisPrefix               = "boost-relay:"
	RedisPrefixKnownValidator = RedisPrefix + "known-validator:"

	defaultExpirationTime = time.Duration(0) // never expires
)

type RedisService struct {
	client *redis.Client
	log    *logrus.Entry
}

func NewRedisService(redisURI string, log *logrus.Entry) (Datastore, error) {
	client, err := connectRedis(redisURI)
	if err != nil {
		return nil, err
	}

	return &RedisService{
		client: client,
		log:    log.WithField("service", "redis"),
	}, nil
}

func RedisKeyKnownValidator(pubKey string) string {
	return RedisPrefixKnownValidator + strings.ToLower(pubKey)
}

func (r *RedisService) GetValidatorRegistration(proposerPubkey types.PublicKey) *types.SignedValidatorRegistration {
	log := r.log.WithField("key", proposerPubkey.String())
	var registration *types.SignedValidatorRegistration
	// Check if the registration is in the cache
	err := r.GetFromCache(RedisKeyKnownValidator(proposerPubkey.String()), &registration)
	if err != nil {
		log.WithError(err).Error("error getting validator registration from cache")
	}
	return registration
}

func (r *RedisService) SaveValidatorRegistration(entry types.SignedValidatorRegistration) {
	log := r.log.WithField("key", entry.Message.Pubkey.String())
	if err := r.SetInCache(RedisKeyKnownValidator(entry.Message.Pubkey.String()), entry); err != nil {
		log.WithError(err).Error("error saving validator registration to cache")
	}
}

func (r *RedisService) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) {
	for _, entry := range entries {
		r.SaveValidatorRegistration(entry)
	}
}

func (r *RedisService) GetFromCache(key string, obj any) error {
	var err error

	value, err := r.client.Get(context.Background(), key).Result()
	if err != nil {
		if err != redis.Nil {
			return err
		}
		return nil
	}

	err = json.Unmarshal([]byte(value), &obj)
	if err != nil {
		return err
	}
	return nil
}

func (r *RedisService) SetInCache(key string, value any) error {
	var err error

	marshalledValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	err = r.client.Set(context.Background(), key, marshalledValue, defaultExpirationTime).Err()
	if err != nil {
		return err
	}
	return nil
}

func connectRedis(redisURI string) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisURI,
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		// unable to connect to redis
		return nil, err
	}
	return redisClient, nil
}
