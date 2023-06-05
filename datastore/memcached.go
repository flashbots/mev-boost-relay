package datastore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	defaultMemcachedExpirySeconds = int32(cli.GetEnvInt("MEMCACHED_EXPIRY_SECONDS", 45))
	defaultMemcachedTimeoutMs     = cli.GetEnvInt("MEMCACHED_CLIENT_TIMEOUT_MS", 250)
	defaultMemcachedMaxIdleConns  = cli.GetEnvInt("MEMCACHED_MAX_IDLE_CONNS", 10)
)

type Memcached struct {
	client    *memcache.Client
	keyPrefix string
}

// SaveExecutionPayload attempts to insert execution engine payload to memcached using composite key of slot,
// proposer public key, block hash, and cache prefix if specified. Note that writes to the same key value
// (i.e. same slot, proposer public key, and block hash) will overwrite the existing entry.
func (m *Memcached) SaveExecutionPayload(slot uint64, proposerPubKey, blockHash string, payload *common.GetPayloadResponse) error {
	// TODO: standardize key format with redis cache and re-use the same function(s)
	key := fmt.Sprintf("boost-relay/%s:cache-getpayload-response:%d_%s_%s", m.keyPrefix, slot, proposerPubKey, blockHash)

	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	//nolint:exhaustruct // "Flags" variable unused and opaque server-side
	return m.client.Set(&memcache.Item{Key: key, Value: bytes, Expiration: defaultMemcachedExpirySeconds})
}

// GetExecutionPayload attempts to fetch execution engine payload from memcached using composite key of slot,
// proposer public key, block hash, and cache prefix if specified.
func (m *Memcached) GetExecutionPayload(slot uint64, proposerPubKey, blockHash string) (*common.VersionedExecutionPayload, error) {
	// TODO: standardize key format with redis cache and re-use the same function(s)
	key := fmt.Sprintf("boost-relay/%s:cache-getpayload-response:%d_%s_%s", m.keyPrefix, slot, proposerPubKey, blockHash)
	item, err := m.client.Get(key)
	if err != nil {
		return nil, err
	}

	result := new(common.VersionedExecutionPayload)
	if err = result.UnmarshalJSON(item.Value); err != nil {
		return nil, err
	}

	return result, nil
}

func NewMemcached(prefix string, servers ...string) (*Memcached, error) {
	if len(servers) == 0 {
		return nil, nil
	}

	sl := new(memcache.ServerList)
	if err := sl.SetServers(servers...); err != nil {
		return nil, err
	}

	client := memcache.NewFromSelector(sl)
	if err := client.Ping(); err != nil {
		return nil, err
	}

	client.MaxIdleConns = defaultMemcachedMaxIdleConns
	client.Timeout = time.Duration(defaultMemcachedTimeoutMs) * time.Millisecond

	return &Memcached{client: client, keyPrefix: prefix}, nil
}
