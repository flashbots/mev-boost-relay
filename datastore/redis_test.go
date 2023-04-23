package datastore

import (
	"math/big"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) *RedisCache {
	t.Helper()
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisService, err := NewRedisCache(redisTestServer.Addr(), "", "")
	require.NoError(t, err)

	return redisService
}

func TestRedisValidatorRegistration(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get validator registration from cache", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator
		pkHex := types.NewPubkeyHex(key.String())
		err := cache.SetValidatorRegistrationTimestamp(pkHex, value.Message.Timestamp)
		require.NoError(t, err)
		result, err := cache.GetValidatorRegistrationTimestamp(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, result, value.Message.Timestamp)
	})

	t.Run("Returns nil if validator registration is not in cache", func(t *testing.T) {
		key := types.PublicKey{}
		result, err := cache.GetValidatorRegistrationTimestamp(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, uint64(0), result)
	})

	t.Run("test SetValidatorRegistrationTimestampIfNewer", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator

		pkHex := types.NewPubkeyHex(key.String())
		timestamp := value.Message.Timestamp

		err := cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp)
		require.NoError(t, err)

		result, err := cache.GetValidatorRegistrationTimestamp(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, result, timestamp)

		// Try to set an older timestamp (should not work)
		timestamp2 := timestamp - 10
		err = cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp2)
		require.NoError(t, err)
		result, err = cache.GetValidatorRegistrationTimestamp(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, result, timestamp)

		// Try to set an older timestamp (should not work)
		timestamp3 := timestamp + 10
		err = cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp3)
		require.NoError(t, err)
		result, err = cache.GetValidatorRegistrationTimestamp(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, result, timestamp3)
	})
}

func TestRedisKnownValidators(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get known validators", func(t *testing.T) {
		key1 := types.NewPubkeyHex("0x1a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
		index1 := uint64(1)
		key2 := types.NewPubkeyHex("0x2a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
		index2 := uint64(2)
		require.NoError(t, cache.SetKnownValidator(key1, index1))
		require.NoError(t, cache.SetKnownValidator(key2, index2))

		knownVals, err := cache.GetKnownValidators()
		require.NoError(t, err)
		require.Equal(t, 2, len(knownVals))
		require.Contains(t, knownVals, index1)
		require.Equal(t, key1, knownVals[index1])
		require.Contains(t, knownVals, index2)
		require.Equal(t, key2, knownVals[index2])
	})
}

func TestRedisValidatorRegistrations(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get validator registrations", func(t *testing.T) {
		key1 := types.NewPubkeyHex("0x1a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
		index1 := uint64(1)
		require.NoError(t, cache.SetKnownValidator(key1, index1))

		knownVals, err := cache.GetKnownValidators()
		require.NoError(t, err)
		require.Equal(t, 1, len(knownVals))
		require.Contains(t, knownVals, index1)

		// Create a signed registration for key1
		pubkey1, err := types.HexToPubkey(knownVals[index1].String())
		require.NoError(t, err)
		entry := types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				FeeRecipient: types.Address{0x02},
				GasLimit:     5000,
				Timestamp:    0xffffffff,
				Pubkey:       pubkey1,
			},
			Signature: types.Signature{},
		}

		pkHex := types.NewPubkeyHex(entry.Message.Pubkey.String())
		err = cache.SetValidatorRegistrationTimestamp(pkHex, entry.Message.Timestamp)
		require.NoError(t, err)

		reg, err := cache.GetValidatorRegistrationTimestamp(key1)
		require.NoError(t, err)
		require.Equal(t, uint64(0xffffffff), reg)
	})
}

func TestRedisProposerDuties(t *testing.T) {
	cache := setupTestRedis(t)
	duties := []types.BuilderGetValidatorsResponseEntry{
		{
			Slot: 1,
			Entry: &types.SignedValidatorRegistration{
				Signature: types.Signature{},
				Message: &types.RegisterValidatorRequestMessage{
					FeeRecipient: types.Address{0x02},
					GasLimit:     5000,
					Timestamp:    0xffffffff,
					Pubkey:       types.PublicKey{},
				},
			},
		},
	}
	err := cache.SetProposerDuties(duties)
	require.NoError(t, err)

	duties2, err := cache.GetProposerDuties()
	require.NoError(t, err)

	require.Equal(t, 1, len(duties2))
	require.Equal(t, duties[0].Entry.Message.FeeRecipient, duties2[0].Entry.Message.FeeRecipient)
}

func TestActiveValidators(t *testing.T) {
	pk1 := types.NewPubkeyHex("0x8016d3229030424cfeff6c5b813970ea193f8d012cfa767270ca9057d58eddc556e96c14544bf4c038dbed5f24aa8da0")
	cache := setupTestRedis(t)
	err := cache.SetActiveValidator(pk1)
	require.NoError(t, err)

	vals, err := cache.GetActiveValidators()
	require.NoError(t, err)
	require.Equal(t, 1, len(vals))
	require.True(t, vals[pk1])
}

func TestBuilderBids(t *testing.T) {
	slot := uint64(2)
	parentHash := "0x13e606c7b3d1faad7e83503ce3dedce4c6bb89b0c28ffb240d713c7b110b9747"
	proposerPubkey := "0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792"
	opts := common.CreateTestBlockSubmissionOpts{
		Slot:           2,
		ParentHash:     parentHash,
		ProposerPubkey: proposerPubkey,
	}

	// Notation:
	// - ba1:  builder A, bid 1
	// - ba1c: builder A, bid 1, cancellation enabled
	//
	// test 1: ba1=10 -> ba2=5 -> ba3c=5 -> bb1=20 -> ba4c=3 -> bb2c=2
	//
	bApubkey := "0xfa1ed37c3553d0ce1e9349b2c5063cf6e394d231c8d3e0df75e9462257c081543086109ffddaacc0aa76f33dc9661c83"
	bBpubkey := "0x2e02be2c9f9eccf9856478fdb7876598fed2da09f45c233969ba647a250231150ecf38bce5771adb6171c86b79a92f16"

	// Setup redis instance
	cache := setupTestRedis(t)

	// Helper to ensure writing to redis worked as expected
	ensureBestBidValueEquals := func(expectedValue int64) {
		bestBid, err := cache.GetBestBid(slot, parentHash, proposerPubkey)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(expectedValue), bestBid.Value())

		topBidValue, err := cache.GetTopBidValue(slot, parentHash, proposerPubkey)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(expectedValue), topBidValue)
	}

	// submit ba1=10
	payload, getPayloadResp, getHeaderResp := common.CreateTestBlockSubmission(t, bApubkey, big.NewInt(10), &opts)
	resp, err := cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), false)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved, resp)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(10), resp.TopBidValue)
	require.Equal(t, bApubkey, resp.TopBidBuilder)
	ensureBestBidValueEquals(10)

	// submit ba2=5 (should not update)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bApubkey, big.NewInt(5), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), false)
	require.NoError(t, err)
	require.False(t, resp.WasBidSaved, resp)
	require.False(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(10), resp.TopBidValue)
	require.Equal(t, bApubkey, resp.TopBidBuilder)
	ensureBestBidValueEquals(10)

	// submit ba3c=5 (should update, because of cancellation)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bApubkey, big.NewInt(5), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), true)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(5), resp.TopBidValue)
	require.Equal(t, bApubkey, resp.TopBidBuilder)
	require.Equal(t, big.NewInt(10), resp.PrevTopBidValue)
	ensureBestBidValueEquals(5)

	// submit bb1=20
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bBpubkey, big.NewInt(20), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), false)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(20), resp.TopBidValue)
	require.Equal(t, bBpubkey, resp.TopBidBuilder)
	ensureBestBidValueEquals(20)

	// submit ba4c=3
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bApubkey, big.NewInt(5), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), true)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.False(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(20), resp.TopBidValue)
	require.Equal(t, bBpubkey, resp.TopBidBuilder)
	ensureBestBidValueEquals(20)

	// submit bb2c=2 (cancels prev top bid bb1)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bBpubkey, big.NewInt(2), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(payload, getPayloadResp, getHeaderResp, time.Now(), true)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(5), resp.TopBidValue)
	require.Equal(t, bApubkey, resp.TopBidBuilder)
	ensureBestBidValueEquals(5)
}

func TestRedisURIs(t *testing.T) {
	t.Helper()
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	// test connection with and without protocol
	_, err = NewRedisCache(redisTestServer.Addr(), "", "")
	require.NoError(t, err)
	_, err = NewRedisCache("redis://"+redisTestServer.Addr(), "", "")
	require.NoError(t, err)

	// test connection w/ credentials
	username := "user"
	password := "pass"
	redisTestServer.RequireUserAuth(username, password)
	fullURL := "redis://" + username + ":" + password + "@" + redisTestServer.Addr()
	_, err = NewRedisCache(fullURL, "", "")
	require.NoError(t, err)

	// ensure malformed URL throws error
	malformURL := "http://" + username + ":" + password + "@" + redisTestServer.Addr()
	_, err = NewRedisCache(malformURL, "", "")
	require.Error(t, err)
	malformURL = "redis://" + username + ":" + "wrongpass" + "@" + redisTestServer.Addr()
	_, err = NewRedisCache(malformURL, "", "")
	require.Error(t, err)
}
