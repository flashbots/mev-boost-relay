package datastore

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/go-redis/redis/v9"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) *RedisCache {
	t.Helper()
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)
	redisService, err := NewRedisCache("", redisTestServer.Addr(), "")
	// redisService, err := NewRedisCache("", "localhost:6379", "")
	require.NoError(t, err)

	return redisService
}

func TestRedisValidatorRegistration(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get validator registration from cache", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator
		pkHex := common.NewPubkeyHex(key.String())
		err := cache.SetValidatorRegistrationTimestamp(pkHex, uint64(value.Message.Timestamp.Unix()))
		require.NoError(t, err)
		result, err := cache.GetValidatorRegistrationTimestamp(common.NewPubkeyHex(key.String()))
		require.NoError(t, err)
		require.Equal(t, result, uint64(value.Message.Timestamp.Unix()))
	})

	t.Run("Returns nil if validator registration is not in cache", func(t *testing.T) {
		key := phase0.BLSPubKey{}
		result, err := cache.GetValidatorRegistrationTimestamp(common.NewPubkeyHex(key.String()))
		require.NoError(t, err)
		require.Equal(t, uint64(0), result)
	})

	t.Run("test SetValidatorRegistrationTimestampIfNewer", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator

		pkHex := common.NewPubkeyHex(key.String())
		timestamp := uint64(value.Message.Timestamp.Unix())

		err := cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp)
		require.NoError(t, err)

		result, err := cache.GetValidatorRegistrationTimestamp(common.NewPubkeyHex(key.String()))
		require.NoError(t, err)
		require.Equal(t, result, timestamp)

		// Try to set an older timestamp (should not work)
		timestamp2 := timestamp - 10
		err = cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp2)
		require.NoError(t, err)
		result, err = cache.GetValidatorRegistrationTimestamp(common.NewPubkeyHex(key.String()))
		require.NoError(t, err)
		require.Equal(t, result, timestamp)

		// Try to set an older timestamp (should not work)
		timestamp3 := timestamp + 10
		err = cache.SetValidatorRegistrationTimestampIfNewer(pkHex, timestamp3)
		require.NoError(t, err)
		result, err = cache.GetValidatorRegistrationTimestamp(common.NewPubkeyHex(key.String()))
		require.NoError(t, err)
		require.Equal(t, result, timestamp3)
	})
}

func TestRedisProposerDuties(t *testing.T) {
	cache := setupTestRedis(t)
	duties := []common.BuilderGetValidatorsResponseEntry{
		{
			Slot: 1,
			Entry: &apiv1.SignedValidatorRegistration{
				Signature: phase0.BLSSignature{},
				Message: &apiv1.ValidatorRegistration{
					FeeRecipient: bellatrix.ExecutionAddress{0x02},
					GasLimit:     5000,
					Timestamp:    time.Unix(0xffffffff, 0),
					Pubkey:       phase0.BLSPubKey{},
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

func TestBuilderBids(t *testing.T) {
	slot := uint64(2)
	parentHash := "0x13e606c7b3d1faad7e83503ce3dedce4c6bb89b0c28ffb240d713c7b110b9747"
	proposerPubkey := "0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792"
	opts := common.CreateTestBlockSubmissionOpts{
		Slot:           2,
		ParentHash:     parentHash,
		ProposerPubkey: proposerPubkey,
	}

	trace := &common.BidTraceV2{
		BidTrace: apiv1.BidTrace{
			Value: uint256.NewInt(123),
		},
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
	ensureBestBidValueEquals := func(expectedValue int64, builderPubkey string) {
		bestBid, err := cache.GetBestBid(slot, parentHash, proposerPubkey)
		require.NoError(t, err)
		value, err := bestBid.Value()
		require.NoError(t, err)
		require.Equal(t, big.NewInt(expectedValue), value.ToBig())

		topBidValue, err := cache.GetTopBidValue(context.Background(), cache.client.Pipeline(), slot, parentHash, proposerPubkey)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(expectedValue), topBidValue)

		if builderPubkey != "" {
			latestBidValue, err := cache.GetBuilderLatestValue(slot, parentHash, proposerPubkey, builderPubkey)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(expectedValue), latestBidValue)
		}
	}

	ensureBidFloor := func(expectedValue int64) {
		floorValue, err := cache.GetFloorBidValue(context.Background(), cache.client.Pipeline(), slot, parentHash, proposerPubkey)
		require.NoError(t, err)
		require.Equal(t, big.NewInt(expectedValue), floorValue)
	}

	// deleting a bid that doesn't exist should not error
	err := cache.DelBuilderBid(context.Background(), cache.client.Pipeline(), slot, parentHash, proposerPubkey, bApubkey)
	require.NoError(t, err)

	// submit ba1=10
	payload, getPayloadResp, getHeaderResp := common.CreateTestBlockSubmission(t, bApubkey, uint256.NewInt(10), &opts)
	resp, err := cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), false, nil)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved, resp)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(10), resp.TopBidValue)
	ensureBestBidValueEquals(10, bApubkey)
	ensureBidFloor(10)

	// deleting ba1
	err = cache.DelBuilderBid(context.Background(), cache.client.Pipeline(), slot, parentHash, proposerPubkey, bApubkey)
	require.NoError(t, err)

	// best bid and floor should still exist, because it was the floor bid
	ensureBestBidValueEquals(10, "")
	ensureBidFloor(10)

	// submit ba2=5 (should not update, because floor is 10)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bApubkey, uint256.NewInt(5), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), false, nil)
	require.NoError(t, err)
	require.False(t, resp.WasBidSaved, resp)
	require.False(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(10), resp.TopBidValue)
	ensureBestBidValueEquals(10, "")
	ensureBidFloor(10)

	// submit ba3c=5 (should not update, because floor is 10)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bApubkey, uint256.NewInt(5), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), true, nil)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.False(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(10), resp.TopBidValue)
	require.Equal(t, big.NewInt(10), resp.PrevTopBidValue)
	ensureBestBidValueEquals(10, "")
	ensureBidFloor(10)

	// submit bb1=20
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bBpubkey, uint256.NewInt(20), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), false, nil)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(20), resp.TopBidValue)
	ensureBestBidValueEquals(20, bBpubkey)
	ensureBidFloor(20)

	// submit bb2c=22
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bBpubkey, uint256.NewInt(22), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), true, nil)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.True(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(22), resp.TopBidValue)
	ensureBestBidValueEquals(22, bBpubkey)
	ensureBidFloor(20)

	// submit bb3c=12 (should update top bid, using floor at 20)
	payload, getPayloadResp, getHeaderResp = common.CreateTestBlockSubmission(t, bBpubkey, uint256.NewInt(12), &opts)
	resp, err = cache.SaveBidAndUpdateTopBid(context.Background(), cache.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), true, nil)
	require.NoError(t, err)
	require.True(t, resp.WasBidSaved)
	require.True(t, resp.WasTopBidUpdated)
	require.False(t, resp.IsNewTopBid)
	require.Equal(t, big.NewInt(20), resp.TopBidValue)
	ensureBestBidValueEquals(20, "")
	ensureBidFloor(20)
}

func TestRedisURIs(t *testing.T) {
	t.Helper()
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	// test connection with and without protocol
	_, err = NewRedisCache("", redisTestServer.Addr(), "")
	require.NoError(t, err)
	_, err = NewRedisCache("", "redis://"+redisTestServer.Addr(), "")
	require.NoError(t, err)

	// test connection w/ credentials
	username := "user"
	password := "pass"
	redisTestServer.RequireUserAuth(username, password)
	fullURL := "redis://" + username + ":" + password + "@" + redisTestServer.Addr()
	_, err = NewRedisCache("", fullURL, "")
	require.NoError(t, err)

	// ensure malformed URL throws error
	malformURL := "http://" + username + ":" + password + "@" + redisTestServer.Addr()
	_, err = NewRedisCache("", malformURL, "")
	require.Error(t, err)
	malformURL = "redis://" + username + ":" + "wrongpass" + "@" + redisTestServer.Addr()
	_, err = NewRedisCache("", malformURL, "")
	require.Error(t, err)
}

func TestCheckAndSetLastSlotAndHashDelivered(t *testing.T) {
	cache := setupTestRedis(t)
	newSlot := uint64(123)
	newHash := "0x0000000000000000000000000000000000000000000000000000000000000000"

	// should return redis.Nil if wasn't set
	slot, err := cache.GetLastSlotDelivered(context.Background(), cache.NewPipeline())
	require.ErrorIs(t, err, redis.Nil)
	require.Equal(t, uint64(0), slot)

	// should be able to set once
	err = cache.CheckAndSetLastSlotAndHashDelivered(newSlot, newHash)
	require.NoError(t, err)

	// should get slot
	slot, err = cache.GetLastSlotDelivered(context.Background(), cache.NewPipeline())
	require.NoError(t, err)
	require.Equal(t, newSlot, slot)

	// should get hash
	hash, err := cache.GetLastHashDelivered()
	require.NoError(t, err)
	require.Equal(t, newHash, hash)

	// should fail on a different payload (mismatch block hash)
	differentHash := "0x0000000000000000000000000000000000000000000000000000000000000001"
	err = cache.CheckAndSetLastSlotAndHashDelivered(newSlot, differentHash)
	require.ErrorIs(t, err, ErrAnotherPayloadAlreadyDeliveredForSlot)

	// should not return error for same hash
	err = cache.CheckAndSetLastSlotAndHashDelivered(newSlot, newHash)
	require.NoError(t, err)

	// should also fail on earlier slots
	err = cache.CheckAndSetLastSlotAndHashDelivered(newSlot-1, newHash)
	require.ErrorIs(t, err, ErrPastSlotAlreadyDelivered)
}

// Test_CheckAndSetLastSlotAndHashDeliveredForTesting ensures the optimistic locking works
// i.e. running CheckAndSetLastSlotAndHashDelivered leading to err == redis.TxFailedErr
func Test_CheckAndSetLastSlotAndHashDeliveredForTesting(t *testing.T) {
	cache := setupTestRedis(t)
	newSlot := uint64(123)
	hash := "0x0000000000000000000000000000000000000000000000000000000000000000"
	n := 3

	errC := make(chan error, n)
	waitC := make(chan bool, n)
	syncWG := sync.WaitGroup{}

	// Kick off goroutines, that will all try to set the same slot
	for i := 0; i < n; i++ {
		syncWG.Add(1)
		go func() {
			errC <- _CheckAndSetLastSlotAndHashDeliveredForTesting(cache, waitC, &syncWG, newSlot, hash)
		}()
	}

	syncWG.Wait()

	// Continue first goroutine (should succeed)
	waitC <- true
	err := <-errC
	require.NoError(t, err)

	// Continue all other goroutines (all should return the race error redis.TxFailedErr)
	for i := 1; i < n; i++ {
		waitC <- true
		err := <-errC
		require.ErrorIs(t, err, redis.TxFailedErr)
	}

	// Any later call with a different hash should return ErrPayloadAlreadyDeliveredForSlot
	differentHash := "0x0000000000000000000000000000000000000000000000000000000000000001"
	err = _CheckAndSetLastSlotAndHashDeliveredForTesting(cache, waitC, &syncWG, newSlot, differentHash)
	waitC <- true
	require.ErrorIs(t, err, ErrAnotherPayloadAlreadyDeliveredForSlot)
}

func _CheckAndSetLastSlotAndHashDeliveredForTesting(r *RedisCache, waitC chan bool, wg *sync.WaitGroup, slot uint64, hash string) (err error) {
	// copied from redis.go, with added channel and waitgroup to test the race condition in a controlled way
	txf := func(tx *redis.Tx) error {
		lastSlotDelivered, err := tx.Get(context.Background(), r.keyLastSlotDelivered).Uint64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}

		if slot < lastSlotDelivered {
			return ErrPastSlotAlreadyDelivered
		}

		if slot == lastSlotDelivered {
			lastHashDelivered, err := tx.Get(context.Background(), r.keyLastHashDelivered).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return err
			}
			if hash != lastHashDelivered {
				return ErrAnotherPayloadAlreadyDeliveredForSlot
			}
			return nil
		}

		wg.Done()
		<-waitC

		_, err = tx.TxPipelined(context.Background(), func(pipe redis.Pipeliner) error {
			pipe.Set(context.Background(), r.keyLastSlotDelivered, slot, 0)
			pipe.Set(context.Background(), r.keyLastHashDelivered, hash, 0)
			return nil
		})

		return err
	}

	return r.client.Watch(context.Background(), txf, r.keyLastSlotDelivered)
}

func TestGetBuilderLatestValue(t *testing.T) {
	cache := setupTestRedis(t)

	slot := uint64(123)
	parentHash := "0x13e606c7b3d1faad7e83503ce3dedce4c6bb89b0c28ffb240d713c7b110b9747"
	proposerPubkey := "0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792"
	builderPubkey := "0xfa1ed37c3553d0ce1e9349b2c5063cf6e394d231c8d3e0df75e9462257c081543086109ffddaacc0aa76f33dc9661c83"

	// With no bids, should return "0".
	v, err := cache.GetBuilderLatestValue(slot, parentHash, proposerPubkey, builderPubkey)
	require.NoError(t, err)
	require.Equal(t, "0", v.String())

	// Set a bid of 1 ETH.
	newVal, err := uint256.FromDecimal("1000000000000000000")
	require.NoError(t, err)
	getHeaderResp := &spec.VersionedSignedBuilderBid{
		Version: consensusspec.DataVersionCapella,
		Capella: &capella.SignedBuilderBid{
			Message: &capella.BuilderBid{
				Value: newVal,
			},
		},
	}

	_, err = cache.client.TxPipelined(context.Background(), func(tx redis.Pipeliner) error {
		return cache.SaveBuilderBid(context.Background(), tx, slot, parentHash, proposerPubkey, builderPubkey, time.Now().UTC(), getHeaderResp)
	})
	require.NoError(t, err)

	// Check new string.
	v, err = cache.GetBuilderLatestValue(slot, parentHash, proposerPubkey, builderPubkey)
	require.NoError(t, err)
	require.Zero(t, v.Cmp(newVal.ToBig()))
}

func TestPipelineNilCheck(t *testing.T) {
	cache := setupTestRedis(t)
	f, err := cache.GetFloorBidValue(context.Background(), cache.NewPipeline(), 0, "1", "2")
	require.NoError(t, err, err)
	require.Equal(t, big.NewInt(0), f)
}

// func TestPipeline(t *testing.T) {
// 	cache := setupTestRedis(t)

// 	key1 := "test1"
// 	key2 := "test123"
// 	val := "foo"
// 	err := cache.client.Set(context.Background(), key1, val, 0).Err()
// 	require.NoError(t, err)

// 	_, err = cache.client.TxPipelined(context.Background(), func(tx redis.Pipeliner) error {
// 		c := tx.Get(context.Background(), key1)
// 		_, err := tx.Exec(context.Background())
// 		require.NoError(t, err)
// 		str, err := c.Result()
// 		require.NoError(t, err)
// 		require.Equal(t, val, str)

// 		err = tx.Set(context.Background(), key2, val, 0).Err()
// 		require.NoError(t, err)
// 		return nil
// 	})
// 	require.NoError(t, err)

// 	str, err := cache.client.Get(context.Background(), key2).Result()
// 	require.NoError(t, err)
// 	require.Equal(t, val, str)
// }
