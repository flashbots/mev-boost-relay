package datastore

import (
	"encoding/json"
	"fmt"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/flashbots/mev-boost-relay/common"
)

const (
	defaultExpirationSeconds = 60
)

type Memcached struct {
	client    *memcache.Client
	keyPrefix string
}

func (m *Memcached) SaveExecutionPayload(slot uint64, proposerPubKey, blockHash string, payload *common.GetPayloadResponse) error {
	if m == nil {
		return nil
	}

	// TODO: standardize key format with redis cache and re-use the same function(s)
	key := fmt.Sprintf("boost-relay/%s:cache-getpayload-response:%d_%s_%s", m.keyPrefix, slot, proposerPubKey, blockHash)

	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	//nolint:exhaustruct // "Flags" variable unused and opaque server-side
	return m.client.Set(&memcache.Item{Key: key, Value: bytes, Expiration: defaultExpirationSeconds})
}

func (m *Memcached) GetExecutionPayload(slot uint64, proposerPubKey, blockHash string) (*common.VersionedExecutionPayload, error) {
	if m == nil {
		return nil, nil
	}

	// TODO: standardize key format with redis cache and re-use the same function(s)
	key := fmt.Sprintf("boost-relay/%s:cache-getpayload-response:%d_%s_%s", m.keyPrefix, slot, proposerPubKey, blockHash)
	item, err := m.client.Get(key)
	if err != nil {
		return nil, err
	}

	var result *common.VersionedExecutionPayload
	if err = json.Unmarshal(item.Value, result); err != nil {
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

	return &Memcached{client: client, keyPrefix: prefix}, nil
}
