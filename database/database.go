// Package database exposes the postgres database
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database/migrations"
	"github.com/flashbots/mev-boost-relay/database/vars"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	migrate "github.com/rubenv/sql-migrate"
)

type IDatabaseService interface {
	NumRegisteredValidators() (count uint64, err error)
	SaveValidatorRegistration(entry ValidatorRegistrationEntry) error
	GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error)
	GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error)
	GetValidatorRegistrationsForPubkeys(pubkeys []string) ([]*ValidatorRegistrationEntry, error)

	SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error, receivedAt time.Time) (entry *BuilderBlockSubmissionEntry, err error)
	GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error)
	GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error)
	GetBuilderSubmissionsBySlots(slotFrom, slotTo uint64) (entries []*BuilderBlockSubmissionEntry, err error)
	GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error)
	GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error)
	GetExecutionPayloads(idFirst, idLast uint64) (entries []*ExecutionPayloadEntry, err error)
	DeleteExecutionPayloads(idFirst, idLast uint64) error

	SaveDeliveredPayload(bidTrace *common.BidTraceV2, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error
	GetNumDeliveredPayloads() (uint64, error)
	GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error)
	GetDeliveredPayloads(idFirst, idLast uint64) (entries []*DeliveredPayloadEntry, err error)

	GetBlockBuilders() ([]*BlockBuilderEntry, error)
	GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error)
	SetBlockBuilderStatus(pubkey string, status common.BuilderStatus) error
	SetBlockBuilderCollateral(pubkey, collateralID, collateralValue string) error
	UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError bool) error
	IncBlockBuilderStatsAfterGetPayload(builderPubkey string) error

	UpsertBuilderDemotion(submitBlockRequest *types.BuilderSubmitBlockRequest, signedBeaconBlock *types.SignedBeaconBlock, signedValidatorRegistration *types.SignedValidatorRegistration) error
}

type DatabaseService struct {
	DB *sqlx.DB

	nstmtInsertExecutionPayload       *sqlx.NamedStmt
	nstmtInsertBlockBuilderSubmission *sqlx.NamedStmt
}

func NewDatabaseService(dsn string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.DB.SetMaxOpenConns(50)
	db.DB.SetMaxIdleConns(10)
	db.DB.SetConnMaxIdleTime(0)

	if os.Getenv("DB_DONT_APPLY_SCHEMA") == "" {
		migrate.SetTable(vars.TableMigrations)
		_, err := migrate.Exec(db.DB, "postgres", migrations.Migrations, migrate.Up)
		if err != nil {
			return nil, err
		}
	}

	dbService := &DatabaseService{DB: db} //nolint:exhaustruct
	err = dbService.prepareNamedQueries()
	return dbService, err
}

func (s *DatabaseService) prepareNamedQueries() (err error) {
	// Insert execution payload
	query := `INSERT INTO ` + vars.TableExecutionPayload + `
	(slot, proposer_pubkey, block_hash, version, payload) VALUES
	(:slot, :proposer_pubkey, :block_hash, :version, :payload)
	ON CONFLICT (slot, proposer_pubkey, block_hash) DO UPDATE SET slot=:slot
	RETURNING id`
	s.nstmtInsertExecutionPayload, err = s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}

	// Insert block builder submission
	query = `INSERT INTO ` + vars.TableBuilderBlockSubmission + `
	(received_at, execution_payload_id, sim_success, sim_error, signature, slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value, epoch, block_number) VALUES
	(:received_at, :execution_payload_id, :sim_success, :sim_error, :signature, :slot, :parent_hash, :block_hash, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :gas_used, :gas_limit, :num_tx, :value, :epoch, :block_number)
	RETURNING id`
	s.nstmtInsertBlockBuilderSubmission, err = s.DB.PrepareNamed(query)
	return err
}

func (s *DatabaseService) Close() error {
	return s.DB.Close()
}

// NumRegisteredValidators returns the number of unique pubkeys that have registered
func (s *DatabaseService) NumRegisteredValidators() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM (SELECT DISTINCT pubkey FROM ` + vars.TableValidatorRegistration + `) AS temp;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}

func (s *DatabaseService) NumValidatorRegistrationRows() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM ` + vars.TableValidatorRegistration + `;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}

func (s *DatabaseService) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	query := `WITH latest_registration AS (
		SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature FROM ` + vars.TableValidatorRegistration + ` WHERE pubkey=:pubkey ORDER BY pubkey, timestamp DESC limit 1
	)
	INSERT INTO ` + vars.TableValidatorRegistration + ` (pubkey, fee_recipient, timestamp, gas_limit, signature)
	SELECT :pubkey, :fee_recipient, :timestamp, :gas_limit, :signature
	WHERE NOT EXISTS (
		SELECT 1 from latest_registration WHERE pubkey=:pubkey AND :timestamp <= latest_registration.timestamp OR (:fee_recipient = latest_registration.fee_recipient AND :gas_limit = latest_registration.gas_limit)
	);`
	_, err := s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature
		FROM ` + vars.TableValidatorRegistration + `
		WHERE pubkey=$1
		ORDER BY pubkey, timestamp DESC;`
	entry := &ValidatorRegistrationEntry{}
	err := s.DB.Get(entry, query, pubkey)
	return entry, err
}

func (s *DatabaseService) GetValidatorRegistrationsForPubkeys(pubkeys []string) (entries []*ValidatorRegistrationEntry, err error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature
		FROM ` + vars.TableValidatorRegistration + `
		WHERE pubkey IN (?)
		ORDER BY pubkey, timestamp DESC;`

	q, args, err := sqlx.In(query, pubkeys)
	if err != nil {
		return nil, err
	}
	err = s.DB.Select(&entries, s.DB.Rebind(q), args...)
	return entries, err
}

func (s *DatabaseService) GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error) {
	// query details: https://stackoverflow.com/questions/3800551/select-first-row-in-each-group-by-group/7630564#7630564
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature`
	if timestampOnly {
		query = `SELECT DISTINCT ON (pubkey) pubkey, timestamp`
	}
	query += ` FROM ` + vars.TableValidatorRegistration + ` ORDER BY pubkey, timestamp DESC;`

	var registrations []*ValidatorRegistrationEntry
	err := s.DB.Select(&registrations, query)
	return registrations, err
}

func (s *DatabaseService) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error, receivedAt time.Time) (entry *BuilderBlockSubmissionEntry, err error) {
	// Save execution_payload: insert, or if already exists update to be able to return the id ('on conflict do nothing' doesn't return an id)
	execPayloadEntry, err := PayloadToExecPayloadEntry(payload)
	if err != nil {
		return nil, err
	}

	err = s.nstmtInsertExecutionPayload.QueryRow(execPayloadEntry).Scan(&execPayloadEntry.ID)
	if err != nil {
		return nil, err
	}

	// Save block_submission
	simErrStr := ""
	if simError != nil {
		simErrStr = simError.Error()
	}

	blockSubmissionEntry := &BuilderBlockSubmissionEntry{
		ReceivedAt:         NewNullTime(receivedAt),
		ExecutionPayloadID: NewNullInt64(execPayloadEntry.ID),

		SimSuccess: simError == nil,
		SimError:   simErrStr,

		Signature: payload.Signature.String(),

		Slot:       payload.Message.Slot,
		BlockHash:  payload.ExecutionPayload.BlockHash.String(),
		ParentHash: payload.ExecutionPayload.ParentHash.String(),

		BuilderPubkey:        payload.Message.BuilderPubkey.String(),
		ProposerPubkey:       payload.Message.ProposerPubkey.String(),
		ProposerFeeRecipient: payload.Message.ProposerFeeRecipient.String(),

		GasUsed:  payload.Message.GasUsed,
		GasLimit: payload.Message.GasLimit,

		NumTx: uint64(len(payload.ExecutionPayload.Transactions)),
		Value: payload.Message.Value.String(),

		Epoch:       payload.Message.Slot / uint64(common.SlotsPerEpoch),
		BlockNumber: payload.ExecutionPayload.BlockNumber,
	}
	err = s.nstmtInsertBlockBuilderSubmission.QueryRow(blockSubmissionEntry).Scan(&blockSubmissionEntry.ID)
	return blockSubmissionEntry, err
}

func (s *DatabaseService) GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error) {
	query := `SELECT id, inserted_at, received_at, execution_payload_id, sim_success, sim_error, signature, slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value, epoch, block_number
	FROM ` + vars.TableBuilderBlockSubmission + `
	WHERE slot=$1 AND proposer_pubkey=$2 AND block_hash=$3
	ORDER BY builder_pubkey ASC
	LIMIT 1`
	entry = &BuilderBlockSubmissionEntry{}
	err = s.DB.Get(entry, query, slot, proposerPubkey, blockHash)
	return entry, err
}

func (s *DatabaseService) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, proposer_pubkey, block_hash, version, payload FROM ` + vars.TableExecutionPayload + ` WHERE id=$1`
	entry = &ExecutionPayloadEntry{}
	err = s.DB.Get(entry, query, executionPayloadID)
	return entry, err
}

func (s *DatabaseService) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, proposer_pubkey, block_hash, version, payload
	FROM ` + vars.TableExecutionPayload + `
	WHERE slot=$1 AND proposer_pubkey=$2 AND block_hash=$3`
	entry = &ExecutionPayloadEntry{}
	err = s.DB.Get(entry, query, slot, proposerPubkey, blockHash)
	return entry, err
}

func (s *DatabaseService) SaveDeliveredPayload(bidTrace *common.BidTraceV2, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error {
	_signedBlindedBeaconBlock, err := json.Marshal(signedBlindedBeaconBlock)
	if err != nil {
		return err
	}

	deliveredPayloadEntry := DeliveredPayloadEntry{
		SignedBlindedBeaconBlock: NewNullString(string(_signedBlindedBeaconBlock)),

		Slot:  bidTrace.Slot,
		Epoch: bidTrace.Slot / uint64(common.SlotsPerEpoch),

		BuilderPubkey:        bidTrace.BuilderPubkey.String(),
		ProposerPubkey:       bidTrace.ProposerPubkey.String(),
		ProposerFeeRecipient: bidTrace.ProposerFeeRecipient.String(),

		ParentHash:  bidTrace.ParentHash.String(),
		BlockHash:   bidTrace.BlockHash.String(),
		BlockNumber: bidTrace.BlockNumber,

		GasUsed:  bidTrace.GasUsed,
		GasLimit: bidTrace.GasLimit,

		NumTx: bidTrace.NumTx,
		Value: bidTrace.Value.String(),
	}

	query := `INSERT INTO ` + vars.TableDeliveredPayload + `
		(signed_blinded_beacon_block, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, gas_used, gas_limit, num_tx, value) VALUES
		(:signed_blinded_beacon_block, :slot, :epoch, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :gas_used, :gas_limit, :num_tx, :value)
		ON CONFLICT DO NOTHING`
	_, err = s.DB.NamedExec(query, deliveredPayloadEntry)
	return err
}

func (s *DatabaseService) GetRecentDeliveredPayloads(queryArgs GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	arg := map[string]interface{}{
		"limit":           queryArgs.Limit,
		"slot":            queryArgs.Slot,
		"cursor":          queryArgs.Cursor,
		"block_hash":      queryArgs.BlockHash,
		"block_number":    queryArgs.BlockNumber,
		"proposer_pubkey": queryArgs.ProposerPubkey,
		"builder_pubkey":  queryArgs.BuilderPubkey,
	}

	fields := "id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"

	whereConds := []string{}
	if queryArgs.Slot > 0 {
		whereConds = append(whereConds, "slot = :slot")
	} else if queryArgs.Cursor > 0 {
		whereConds = append(whereConds, "slot <= :cursor")
	}
	if queryArgs.BlockHash != "" {
		whereConds = append(whereConds, "block_hash = :block_hash")
	}
	if queryArgs.BlockNumber > 0 {
		whereConds = append(whereConds, "block_number = :block_number")
	}
	if queryArgs.ProposerPubkey != "" {
		whereConds = append(whereConds, "proposer_pubkey = :proposer_pubkey")
	}
	if queryArgs.BuilderPubkey != "" {
		whereConds = append(whereConds, "builder_pubkey = :builder_pubkey")
	}

	where := ""
	if len(whereConds) > 0 {
		where = "WHERE " + strings.Join(whereConds, " AND ")
	}

	orderBy := "slot DESC"
	if queryArgs.OrderByValue == 1 {
		orderBy = "value ASC"
	} else if queryArgs.OrderByValue == -1 {
		orderBy = "value DESC"
	}

	query := fmt.Sprintf("SELECT %s FROM %s %s ORDER BY %s LIMIT :limit", fields, vars.TableDeliveredPayload, where, orderBy)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	entries := []*DeliveredPayloadEntry{}
	rows, err := s.DB.NamedQueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		entry := new(DeliveredPayloadEntry)
		err = rows.StructScan(entry)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *DatabaseService) GetDeliveredPayloads(idFirst, idLast uint64) (entries []*DeliveredPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit
	FROM ` + vars.TableDeliveredPayload + `
	WHERE id >= $1 AND id <= $2
	ORDER BY slot ASC`

	err = s.DB.Select(&entries, query, idFirst, idLast)
	return entries, err
}

func (s *DatabaseService) GetNumDeliveredPayloads() (uint64, error) {
	var count uint64
	err := s.DB.QueryRow("SELECT COUNT(*) FROM " + vars.TableDeliveredPayload).Scan(&count)
	return count, err
}

func (s *DatabaseService) GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error) {
	arg := map[string]interface{}{
		"limit":          filters.Limit,
		"slot":           filters.Slot,
		"block_hash":     filters.BlockHash,
		"block_number":   filters.BlockNumber,
		"builder_pubkey": filters.BuilderPubkey,
	}

	fields := "id, inserted_at, received_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"
	limit := "LIMIT :limit"

	whereConds := []string{
		"sim_success = true",
	}
	if filters.Slot > 0 {
		whereConds = append(whereConds, "slot = :slot")
		limit = "" // remove the limit when filtering by slot
	}
	if filters.BlockNumber > 0 {
		whereConds = append(whereConds, "block_number = :block_number")
		limit = "" // remove the limit when filtering by block_number
	}
	if filters.BlockHash != "" {
		whereConds = append(whereConds, "block_hash = :block_hash")
		limit = "" // remove the limit when filtering by block_hash
	}
	if filters.BuilderPubkey != "" {
		whereConds = append(whereConds, "builder_pubkey = :builder_pubkey")
	}

	where := ""
	if len(whereConds) > 0 {
		where = "WHERE " + strings.Join(whereConds, " AND ")
	}

	query := fmt.Sprintf("SELECT %s FROM %s %s ORDER BY slot DESC, inserted_at DESC %s", fields, vars.TableBuilderBlockSubmission, where, limit)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	entries := []*BuilderBlockSubmissionEntry{}
	rows, err := s.DB.NamedQueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		entry := new(BuilderBlockSubmissionEntry)
		err = rows.StructScan(entry)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *DatabaseService) GetBuilderSubmissionsBySlots(slotFrom, slotTo uint64) (entries []*BuilderBlockSubmissionEntry, err error) {
	query := `SELECT id, inserted_at, received_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit
	FROM ` + vars.TableBuilderBlockSubmission + `
	WHERE sim_success = true AND slot >= $1 AND slot <= $2
	ORDER BY slot ASC, inserted_at ASC`

	err = s.DB.Select(&entries, query, slotFrom, slotTo)
	return entries, err
}

func (s *DatabaseService) UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError bool) error {
	entry := BlockBuilderEntry{
		BuilderPubkey:          lastSubmission.BuilderPubkey,
		LastSubmissionID:       NewNullInt64(lastSubmission.ID),
		LastSubmissionSlot:     lastSubmission.Slot,
		NumSubmissionsTotal:    1,
		NumSubmissionsSimError: 0,
		CollateralValue:        "0", // required to satisfy numeric type, will not override collateral
	}
	if isError {
		entry.NumSubmissionsSimError = 1
	}

	// Upsert
	query := `INSERT INTO ` + vars.TableBlockBuilder + `
		(builder_pubkey, description, is_high_prio, is_blacklisted, is_demoted, collateral_value, collateral_id, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror) VALUES
		(:builder_pubkey, :description, :is_high_prio, :is_blacklisted, :is_demoted, :collateral_value, :collateral_id, :last_submission_id, :last_submission_slot, :num_submissions_total, :num_submissions_simerror)
		ON CONFLICT (builder_pubkey) DO UPDATE SET
			last_submission_id = :last_submission_id,
			last_submission_slot = :last_submission_slot,
			num_submissions_total = ` + vars.TableBlockBuilder + `.num_submissions_total + 1,
			num_submissions_simerror = ` + vars.TableBlockBuilder + `.num_submissions_simerror + :num_submissions_simerror;`
	_, err := s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) GetBlockBuilders() ([]*BlockBuilderEntry, error) {
	query := `SELECT id, inserted_at, builder_pubkey, description, is_high_prio, is_blacklisted, is_demoted, collateral_value, collateral_id, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_sent_getpayload FROM ` + vars.TableBlockBuilder + ` ORDER BY id ASC;`
	entries := []*BlockBuilderEntry{}
	err := s.DB.Select(&entries, query)
	return entries, err
}

func (s *DatabaseService) GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error) {
	query := `SELECT id, inserted_at, builder_pubkey, description, is_high_prio, is_blacklisted, is_demoted, collateral_value, collateral_id, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_sent_getpayload FROM ` + vars.TableBlockBuilder + ` WHERE builder_pubkey=$1;`
	entry := &BlockBuilderEntry{}
	err := s.DB.Get(entry, query, pubkey)
	return entry, err
}

func (s *DatabaseService) SetBlockBuilderStatus(pubkey string, status common.BuilderStatus) error {
	builder, err := s.GetBlockBuilderByPubkey(pubkey)
	if err != nil {
		return fmt.Errorf("unable to read block builder: %v, %v", pubkey, err)
	}
	var query string
	queryPrefix := `UPDATE ` + vars.TableBlockBuilder + ` SET is_high_prio=$1, is_blacklisted=$2, is_demoted=$3 `
	// If no collateral ID is present, just update the status of the single builder pubkey.
	if builder.CollateralID == "" {
		query = queryPrefix + "WHERE builder_pubkey=$4;"
		_, err := s.DB.Exec(query, status.IsHighPrio, status.IsBlacklisted, status.IsDemoted, pubkey)
		return err
	}
	// If there is a collateral ID, then update statuses of all pubkeys.
	query = queryPrefix + "WHERE collateral_id=$4;"
	_, err = s.DB.Exec(query, status.IsHighPrio, status.IsBlacklisted, status.IsDemoted, builder.CollateralID)
	return err
}

func (s *DatabaseService) SetBlockBuilderCollateral(pubkey, collateralID, collateralValue string) error {
	query := `UPDATE ` + vars.TableBlockBuilder + ` SET collateral_id=$1, collateral_value=$2 WHERE builder_pubkey=$3;`
	_, err := s.DB.Exec(query, collateralID, collateralValue, pubkey)
	return err
}

func (s *DatabaseService) IncBlockBuilderStatsAfterGetPayload(builderPubkey string) error {
	query := `UPDATE ` + vars.TableBlockBuilder + `
		SET num_sent_getpayload=num_sent_getpayload+1
		WHERE builder_pubkey=$1;`
	_, err := s.DB.Exec(query, builderPubkey)
	return err
}

func (s *DatabaseService) GetExecutionPayloads(idFirst, idLast uint64) (entries []*ExecutionPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, proposer_pubkey, block_hash, version, payload FROM ` + vars.TableExecutionPayload + ` WHERE id >= $1 AND id <= $2 ORDER BY id ASC`
	err = s.DB.Select(&entries, query, idFirst, idLast)
	return entries, err
}

func (s *DatabaseService) DeleteExecutionPayloads(idFirst, idLast uint64) error {
	query := `DELETE FROM ` + vars.TableExecutionPayload + ` WHERE id >= $1 AND id <= $2`
	_, err := s.DB.Exec(query, idFirst, idLast)
	return err
}

func (s *DatabaseService) UpsertBuilderDemotion(submitBlockRequest *types.BuilderSubmitBlockRequest, signedBeaconBlock *types.SignedBeaconBlock, signedValidatorRegistration *types.SignedValidatorRegistration) error {
	if submitBlockRequest == nil {
		return fmt.Errorf("nil submitBlockRequest invalid for UpsertBuilderDemotion")
	}

	_submitBlockRequest, err := json.Marshal(submitBlockRequest)
	if err != nil {
		return err
	}
	bidTrace := submitBlockRequest.Message
	builderDemotionEntry := BuilderDemotionEntry{
		SubmitBlockRequest: NewNullString(string(_submitBlockRequest)),

		Slot:  bidTrace.Slot,
		Epoch: bidTrace.Slot / uint64(common.SlotsPerEpoch),

		BuilderPubkey:  bidTrace.BuilderPubkey.String(),
		ProposerPubkey: bidTrace.ProposerPubkey.String(),

		Value: bidTrace.Value.String(),

		BlockHash: bidTrace.BlockHash.String(),
	}

	if signedBeaconBlock != nil {
		_signedBeaconBlock, err := json.Marshal(signedBeaconBlock)
		if err != nil {
			return err
		}
		_signedValidatorRegistration, err := json.Marshal(signedValidatorRegistration)
		if err != nil {
			return err
		}
		builderDemotionEntry.SignedBeaconBlock = NewNullString(string(_signedBeaconBlock))
		builderDemotionEntry.SignedValidatorRegistration = NewNullString(string(_signedValidatorRegistration))
	}

	queryPrefix := `INSERT INTO ` + vars.TableBuilderDemotions + `
		(submit_block_request, signed_beacon_block, signed_validator_registration, slot, epoch, builder_pubkey, proposer_pubkey, value, fee_recipient, block_hash) VALUES
		(:submit_block_request, :signed_beacon_block, :signed_validator_registration, :slot, :epoch, :builder_pubkey, :proposer_pubkey, :value, :fee_recipient, :block_hash)
		ON CONFLICT (block_hash, builder_pubkey) 
		`
	var query string
	// If block_hash + builder_pubkey conflicts and we have a published block, fill in fields needed for the refund.
	if signedBeaconBlock != nil {
		query = queryPrefix + `
		DO UPDATE SET
			signed_beacon_block = :signed_beacon_block,
			signed_validator_registration = :signed_validator_registration,
			fee_recipient = :fee_recipient;
		`
	} else {
		// If the block_hash + builder_pubkey conflicts, but no signedBeaconBlock, then do nothing.
		query = queryPrefix + "DO NOTHING;"
	}
	_, err = s.DB.NamedExec(query, builderDemotionEntry)
	return err
}
