package database

import (
	"os"
	"testing"
	"time"

	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database/migrations"
	"github.com/flashbots/mev-boost-relay/database/vars"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
)

const (
	slot          = uint64(42)
	collateral    = 1000
	collateralStr = "1000"
	collateralID  = "builder0x69"
	randao        = "01234567890123456789012345678901"
)

var (
	runDBTests   = os.Getenv("RUN_DB_TESTS") == "1" //|| true
	feeRecipient = types.Address{0x02}
	testDBDSN    = common.GetEnv("TEST_DB_DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
)

func createValidatorRegistration(pubKey string) ValidatorRegistrationEntry {
	return ValidatorRegistrationEntry{
		Pubkey:       pubKey,
		FeeRecipient: "0xffbb8996515293fcd87ca09b5c6ffe5c17f043c6",
		Timestamp:    1663311456,
		GasLimit:     30000000,
		Signature:    "0xab6fa6462f658708f1a9030faeac588d55b1e28cc1f506b3ef938eeeec0171d4209865fb66bbb94e52c0c160a63975e51795ee8d1da38219b3f80d7d14f003421a255d99b744bd71f45f0cb2cd17948afff67ad6c9163fcd20b48f6315dac7cc",
	}
}

func getTestKeyPair(t *testing.T) (*types.PublicKey, *blst.SecretKey) {
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	blsPubkey := bls.PublicKeyFromSecretKey(sk)
	var pubkey types.PublicKey
	err = pubkey.FromSlice(blsPubkey.Compress())
	require.NoError(t, err)
	return &pubkey, sk
}

func insertTestBuilder(t *testing.T, db IDatabaseService) string {
	pk, sk := getTestKeyPair(t)
	req := common.TestBuilderSubmitBlockRequest(pk, sk, &types.BidTrace{
		Slot:                 slot,
		BuilderPubkey:        *pk,
		ProposerFeeRecipient: feeRecipient,
		Value:                types.IntToU256(uint64(collateral)),
	})
	entry, err := db.SaveBuilderBlockSubmission(&req, nil, time.Now())
	require.NoError(t, err)
	err = db.UpsertBlockBuilderEntryAfterSubmission(entry, false)
	require.NoError(t, err)
	return req.Message.BuilderPubkey.String()
}

func resetDatabase(t *testing.T) *DatabaseService {
	t.Helper()
	if !runDBTests {
		t.Skip("Skipping database tests")
	}

	// Wipe test database
	_db, err := sqlx.Connect("postgres", testDBDSN)
	require.NoError(t, err)
	_, err = _db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
	require.NoError(t, err)

	db, err := NewDatabaseService(testDBDSN)
	require.NoError(t, err)
	return db
}

func TestSaveValidatorRegistration(t *testing.T) {
	db := resetDatabase(t)

	// reg1 is the initial registration
	reg1 := createValidatorRegistration("0x8996515293fcd87ca09b5c6ffe5c17f043c6a1a3639cc9494a82ec8eb50a9b55c34b47675e573be40d9be308b1ca2908")

	// reg2 is reg1 with newer timestamp, same fields - should not insert
	reg2 := createValidatorRegistration("0x8996515293fcd87ca09b5c6ffe5c17f043c6a1a3639cc9494a82ec8eb50a9b55c34b47675e573be40d9be308b1ca2908")
	reg2.Timestamp = reg1.Timestamp + 1

	// reg3 is reg1 with newer timestamp and new gaslimit - insert
	reg3 := createValidatorRegistration("0x8996515293fcd87ca09b5c6ffe5c17f043c6a1a3639cc9494a82ec8eb50a9b55c34b47675e573be40d9be308b1ca2908")
	reg3.Timestamp = reg1.Timestamp + 1
	reg3.GasLimit = reg1.GasLimit + 1

	// reg4 is reg1 with newer timestamp and new fee_recipient - insert
	reg4 := createValidatorRegistration("0x8996515293fcd87ca09b5c6ffe5c17f043c6a1a3639cc9494a82ec8eb50a9b55c34b47675e573be40d9be308b1ca2908")
	reg4.Timestamp = reg1.Timestamp + 2
	reg4.FeeRecipient = "0xafbb8996515293fcd87ca09b5c6ffe5c17f043c6"

	// reg5 is reg1 with older timestamp and new fee_recipient - should not insert
	reg5 := createValidatorRegistration("0x8996515293fcd87ca09b5c6ffe5c17f043c6a1a3639cc9494a82ec8eb50a9b55c34b47675e573be40d9be308b1ca2908")
	reg5.Timestamp = reg1.Timestamp - 1
	reg5.FeeRecipient = "0x00bb8996515293fcd87ca09b5c6ffe5c17f043c6"

	// Require empty DB
	cnt, err := db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(0), cnt, "DB not empty to start")

	// Save reg1
	err = db.SaveValidatorRegistration(reg1)
	require.NoError(t, err)
	regX1, err := db.GetValidatorRegistration(reg1.Pubkey)
	require.NoError(t, err)
	require.Equal(t, reg1.FeeRecipient, regX1.FeeRecipient)
	cnt, err = db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(1), cnt)

	// Save reg2, should not insert
	err = db.SaveValidatorRegistration(reg2)
	require.NoError(t, err)
	regX1, err = db.GetValidatorRegistration(reg1.Pubkey)
	require.NoError(t, err)
	require.Equal(t, reg1.Timestamp, regX1.Timestamp)
	cnt, err = db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(1), cnt)

	// Save reg3, should insert
	err = db.SaveValidatorRegistration(reg3)
	require.NoError(t, err)
	regX1, err = db.GetValidatorRegistration(reg1.Pubkey)
	require.NoError(t, err)
	require.Equal(t, reg3.Timestamp, regX1.Timestamp)
	require.Equal(t, reg3.GasLimit, regX1.GasLimit)
	cnt, err = db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(2), cnt)

	// Save reg4, should insert
	err = db.SaveValidatorRegistration(reg4)
	require.NoError(t, err)
	regX1, err = db.GetValidatorRegistration(reg1.Pubkey)
	require.NoError(t, err)
	require.Equal(t, reg4.Timestamp, regX1.Timestamp)
	require.Equal(t, reg4.GasLimit, regX1.GasLimit)
	require.Equal(t, reg4.FeeRecipient, regX1.FeeRecipient)
	cnt, err = db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(3), cnt)

	// Save reg5, should not insert
	err = db.SaveValidatorRegistration(reg5)
	require.NoError(t, err)
	regX1, err = db.GetValidatorRegistration(reg1.Pubkey)
	require.NoError(t, err)
	require.Equal(t, reg4.Timestamp, regX1.Timestamp)
	require.Equal(t, reg4.GasLimit, regX1.GasLimit)
	require.Equal(t, reg4.FeeRecipient, regX1.FeeRecipient)
	cnt, err = db.NumValidatorRegistrationRows()
	require.NoError(t, err)
	require.Equal(t, uint64(3), cnt)
}

func TestMigrations(t *testing.T) {
	db := resetDatabase(t)
	query := `SELECT COUNT(*) FROM ` + vars.TableMigrations + `;`
	rowCount := 0
	err := db.DB.QueryRow(query).Scan(&rowCount)
	require.NoError(t, err)
	require.Equal(t, len(migrations.Migrations.Migrations), rowCount)
}

func TestSetBlockBuilderStatus(t *testing.T) {
	db := resetDatabase(t)
	// Four test builders, 2 with matching collateral id, 2 with no collateral id.
	pubkey1 := insertTestBuilder(t, db)
	pubkey2 := insertTestBuilder(t, db)
	pubkey3 := insertTestBuilder(t, db)
	pubkey4 := insertTestBuilder(t, db)

	// Builder 1 & 2 share a collateral id.
	err := db.SetBlockBuilderCollateral(pubkey1, collateralID, collateralStr)
	require.NoError(t, err)
	err = db.SetBlockBuilderCollateral(pubkey2, collateralID, collateralStr)
	require.NoError(t, err)

	// Before status change.
	for _, v := range []string{pubkey1, pubkey2, pubkey3, pubkey4} {
		builder, err := db.GetBlockBuilderByPubkey(v)
		require.NoError(t, err)
		require.False(t, builder.IsHighPrio)
		require.False(t, builder.IsDemoted)
		require.False(t, builder.IsBlacklisted)
	}

	// Update status of builder 1 and 3.
	err = db.SetBlockBuilderStatus(pubkey1, common.BuilderStatus{
		IsHighPrio: true,
		IsDemoted:  true,
	})
	require.NoError(t, err)
	err = db.SetBlockBuilderStatus(pubkey3, common.BuilderStatus{
		IsHighPrio: true,
		IsDemoted:  true,
	})
	require.NoError(t, err)

	// After status change, builders 1, 2, 3 should be modified.
	for _, v := range []string{pubkey1, pubkey2, pubkey3} {
		builder, err := db.GetBlockBuilderByPubkey(v)
		require.NoError(t, err)
		require.True(t, builder.IsHighPrio)
		require.True(t, builder.IsDemoted)
		require.False(t, builder.IsBlacklisted)
	}
	// Builder 4 should be unchanged.
	builder, err := db.GetBlockBuilderByPubkey(pubkey4)
	require.NoError(t, err)
	require.False(t, builder.IsHighPrio)
	require.False(t, builder.IsDemoted)
	require.False(t, builder.IsBlacklisted)
}

func TestSetBlockBuilderCollateral(t *testing.T) {
	db := resetDatabase(t)
	pubkey := insertTestBuilder(t, db)

	// Before collateral change.
	builder, err := db.GetBlockBuilderByPubkey(pubkey)
	require.NoError(t, err)
	require.Equal(t, "", builder.CollateralID)
	require.Equal(t, "0", builder.CollateralValue)

	err = db.SetBlockBuilderCollateral(pubkey, collateralID, collateralStr)
	require.NoError(t, err)

	// After collateral change.
	builder, err = db.GetBlockBuilderByPubkey(pubkey)
	require.NoError(t, err)
	require.Equal(t, collateralID, builder.CollateralID)
	require.Equal(t, collateralStr, builder.CollateralValue)
}

func TestUpsertBuilderDemotion(t *testing.T) {
	db := resetDatabase(t)
	pk, sk := getTestKeyPair(t)
	req := common.TestBuilderSubmitBlockRequest(pk, sk, &types.BidTrace{
		Slot:                 slot,
		BuilderPubkey:        *pk,
		ProposerFeeRecipient: feeRecipient,
		Value:                types.IntToU256(uint64(collateral)),
	})

	// Non-refundable demotion (just the block request).
	err := db.UpsertBuilderDemotion(&req, nil, nil)
	require.NoError(t, err)

	// Refundable demotion.
	err = db.UpsertBuilderDemotion(&req, &types.SignedBeaconBlock{}, &types.SignedValidatorRegistration{})
	require.NoError(t, err)
}
