// Package database exposes the postgres database
package database

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type IDatabaseService interface {
	NumRegisteredValidators() (count uint64, err error)
	SaveValidatorRegistration(entry ValidatorRegistrationEntry) error
	GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error)
	GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error)
	GetValidatorRegistrationsForPubkeys(pubkeys []string) ([]*ValidatorRegistrationEntry, error)

	SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error, isMostProfitable bool) (entry *BuilderBlockSubmissionEntry, err error)
	GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error)
	GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error)
	GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error)
	GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error)

	SaveDeliveredPayload(slot uint64, proposerPubkey types.PubkeyHex, blockHash types.Hash, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error
	GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error)
	GetNumDeliveredPayloads() (uint64, error)

	GetBlockBuilders() ([]*BlockBuilderEntry, error)
	GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error)
	SetBlockBuilderStatus(pubkey string, isHighPrio, isBlacklisted bool) error
	UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError, isTopbid bool) error
	IncBlockBuilderStatsAfterGetPayload(slot uint64, blockhash string) error
}

type DatabaseService struct {
	DB *sqlx.DB
}

func NewDatabaseService(dsn string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.DB.SetMaxOpenConns(50)
	db.DB.SetMaxIdleConns(10)
	db.DB.SetConnMaxIdleTime(0)

	if os.Getenv("PRINT_SCHEMA") == "1" {
		fmt.Println(schema)
	}

	if os.Getenv("DB_DONT_APPLY_SCHEMA") == "" {
		_, err = db.Exec(schema)
		if err != nil {
			return nil, err
		}
	}

	return &DatabaseService{
		DB: db,
	}, nil
}

func (s *DatabaseService) Close() error {
	return s.DB.Close()
}

// NumRegisteredValidators returns the number of unique pubkeys that have registered
func (s *DatabaseService) NumRegisteredValidators() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM (SELECT DISTINCT pubkey FROM ` + TableValidatorRegistration + `) AS temp;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}

func (s *DatabaseService) NumValidatorRegistrationRows() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM ` + TableValidatorRegistration + `;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}

func (s *DatabaseService) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	query := `WITH latest_registration AS (
		SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature FROM ` + TableValidatorRegistration + ` WHERE pubkey=:pubkey ORDER BY pubkey, timestamp DESC limit 1
	)
	INSERT INTO ` + TableValidatorRegistration + ` (pubkey, fee_recipient, timestamp, gas_limit, signature)
	SELECT :pubkey, :fee_recipient, :timestamp, :gas_limit, :signature
	WHERE NOT EXISTS (
		SELECT 1 from latest_registration WHERE pubkey=:pubkey AND :timestamp <= latest_registration.timestamp OR (:fee_recipient = latest_registration.fee_recipient AND :gas_limit = latest_registration.gas_limit)
	);`
	_, err := s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature
		FROM ` + TableValidatorRegistration + `
		WHERE pubkey=$1
		ORDER BY pubkey, timestamp DESC;`
	entry := &ValidatorRegistrationEntry{}
	err := s.DB.Get(entry, query, pubkey)
	return entry, err
}

func (s *DatabaseService) GetValidatorRegistrationsForPubkeys(pubkeys []string) (entries []*ValidatorRegistrationEntry, err error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature
		FROM ` + TableValidatorRegistration + `
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
	query += ` FROM ` + TableValidatorRegistration + ` ORDER BY pubkey, timestamp DESC;`

	var registrations []*ValidatorRegistrationEntry
	err := s.DB.Select(&registrations, query)
	return registrations, err
}

func (s *DatabaseService) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error, isMostProfitable bool) (entry *BuilderBlockSubmissionEntry, err error) {
	// Save execution_payload: insert, or if already exists update to be able to return the id ('on conflict do nothing' doesn't return an id)
	execPayloadEntry, err := PayloadToExecPayloadEntry(payload)
	if err != nil {
		return nil, err
	}
	query := `INSERT INTO ` + TableExecutionPayload + `
	(slot, proposer_pubkey, block_hash, version, payload) VALUES
	(:slot, :proposer_pubkey, :block_hash, :version, :payload)
	ON CONFLICT (slot, proposer_pubkey, block_hash) DO UPDATE SET slot=:slot
	RETURNING id`
	nstmt, err := s.DB.PrepareNamed(query)
	if err != nil {
		return nil, err
	}
	err = nstmt.QueryRow(execPayloadEntry).Scan(&execPayloadEntry.ID)
	if err != nil {
		return nil, err
	}

	// Save block_submission
	simErrStr := ""
	if simError != nil {
		simErrStr = simError.Error()
	}

	blockSubmissionEntry := &BuilderBlockSubmissionEntry{
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

		NumTx: len(payload.ExecutionPayload.Transactions),
		Value: payload.Message.Value.String(),

		Epoch:             payload.Message.Slot / uint64(common.SlotsPerEpoch),
		BlockNumber:       payload.ExecutionPayload.BlockNumber,
		WasMostProfitable: isMostProfitable,
	}
	query = `INSERT INTO ` + TableBuilderBlockSubmission + `
	(execution_payload_id, sim_success, sim_error, signature, slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value, epoch, block_number, was_most_profitable) VALUES
	(:execution_payload_id, :sim_success, :sim_error, :signature, :slot, :parent_hash, :block_hash, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :gas_used, :gas_limit, :num_tx, :value, :epoch, :block_number, :was_most_profitable)
	RETURNING id`
	nstmt, err = s.DB.PrepareNamed(query)
	if err != nil {
		return nil, err
	}
	err = nstmt.QueryRow(blockSubmissionEntry).Scan(&blockSubmissionEntry.ID)
	if err != nil {
		return nil, err
	}

	return blockSubmissionEntry, err
}

func (s *DatabaseService) GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error) {
	query := `SELECT id, inserted_at, execution_payload_id, sim_success, sim_error, signature, slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value, epoch, block_number
	FROM ` + TableBuilderBlockSubmission + `
	WHERE slot=$1 AND proposer_pubkey=$2 AND block_hash=$3
	ORDER BY builder_pubkey ASC
	LIMIT 1`
	entry = &BuilderBlockSubmissionEntry{}
	err = s.DB.Get(entry, query, slot, proposerPubkey, blockHash)
	return entry, err
}

func (s *DatabaseService) GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, proposer_pubkey, block_hash, version, payload FROM ` + TableExecutionPayload + ` WHERE id=$1`
	entry = &ExecutionPayloadEntry{}
	err = s.DB.Get(entry, query, executionPayloadID)
	return entry, err
}

func (s *DatabaseService) GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error) {
	query := `SELECT id, inserted_at, slot, proposer_pubkey, block_hash, version, payload
	FROM ` + TableExecutionPayload + `
	WHERE slot=$1 AND proposer_pubkey=$2 AND block_hash=$3`
	entry = &ExecutionPayloadEntry{}
	err = s.DB.Get(entry, query, slot, proposerPubkey, blockHash)
	return entry, err
}

func (s *DatabaseService) SaveDeliveredPayload(slot uint64, proposerPubkey types.PubkeyHex, blockHash types.Hash, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error {
	blockSubmissionEntry, err := s.GetBlockSubmissionEntry(slot, proposerPubkey.String(), blockHash.String())
	if err != nil {
		return err
	}

	_signedBlindedBeaconBlock, err := json.Marshal(signedBlindedBeaconBlock)
	if err != nil {
		return err
	}

	deliveredPayloadEntry := DeliveredPayloadEntry{
		ExecutionPayloadID:       blockSubmissionEntry.ExecutionPayloadID,
		SignedBlindedBeaconBlock: NewNullString(string(_signedBlindedBeaconBlock)),

		Slot:  blockSubmissionEntry.Slot,
		Epoch: blockSubmissionEntry.Epoch,

		BuilderPubkey:        blockSubmissionEntry.BuilderPubkey,
		ProposerPubkey:       blockSubmissionEntry.ProposerPubkey,
		ProposerFeeRecipient: blockSubmissionEntry.ProposerFeeRecipient,

		ParentHash:  blockSubmissionEntry.ParentHash,
		BlockHash:   blockSubmissionEntry.BlockHash,
		BlockNumber: blockSubmissionEntry.BlockNumber,

		GasUsed:  blockSubmissionEntry.GasUsed,
		GasLimit: blockSubmissionEntry.GasLimit,

		NumTx: blockSubmissionEntry.NumTx,
		Value: blockSubmissionEntry.Value,
	}

	query := `INSERT INTO ` + TableDeliveredPayload + `
		(execution_payload_id, signed_blinded_beacon_block, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, gas_used, gas_limit, num_tx, value) VALUES
		(:execution_payload_id, :signed_blinded_beacon_block, :slot, :epoch, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :gas_used, :gas_limit, :num_tx, :value)
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

	tasks := []*DeliveredPayloadEntry{}
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

	orderBy := "id DESC"
	if queryArgs.OrderByValue == 1 {
		orderBy = "value ASC"
	} else if queryArgs.OrderByValue == -1 {
		orderBy = "value DESC"
	}

	nstmt, err := s.DB.PrepareNamed(fmt.Sprintf("SELECT %s FROM %s %s ORDER BY %s LIMIT :limit", fields, TableDeliveredPayload, where, orderBy))
	if err != nil {
		return nil, err
	}

	err = nstmt.Select(&tasks, arg)
	return tasks, err
}

func (s *DatabaseService) GetNumDeliveredPayloads() (uint64, error) {
	var count uint64
	err := s.DB.QueryRow("SELECT COUNT(*) FROM " + TableDeliveredPayload).Scan(&count)
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

	tasks := []*BuilderBlockSubmissionEntry{}
	fields := "id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"

	whereConds := []string{
		"sim_success = true",
		"was_most_profitable = true",
	}
	if filters.Slot > 0 {
		whereConds = append(whereConds, "slot = :slot")
	}
	if filters.BlockHash != "" {
		whereConds = append(whereConds, "block_hash = :block_hash")
	}
	if filters.BlockNumber > 0 {
		whereConds = append(whereConds, "block_number = :block_number")
	}
	if filters.BuilderPubkey != "" {
		whereConds = append(whereConds, "builder_pubkey = :builder_pubkey")
	}

	where := ""
	if len(whereConds) > 0 {
		where = "WHERE " + strings.Join(whereConds, " AND ")
	}

	nstmt, err := s.DB.PrepareNamed(fmt.Sprintf("SELECT %s FROM %s %s ORDER BY id DESC LIMIT :limit", fields, TableBuilderBlockSubmission, where))
	if err != nil {
		return nil, err
	}

	err = nstmt.Select(&tasks, arg)
	return tasks, err
}

func (s *DatabaseService) UpsertBlockBuilderEntryAfterSubmission(lastSubmission *BuilderBlockSubmissionEntry, isError, isTopbid bool) error {
	entry := BlockBuilderEntry{
		BuilderPubkey:          lastSubmission.BuilderPubkey,
		LastSubmissionID:       NewNullInt64(lastSubmission.ID),
		LastSubmissionSlot:     lastSubmission.Slot,
		NumSubmissionsTotal:    1,
		NumSubmissionsSimError: 0,
		NumSubmissionsTopBid:   0,
	}
	if isError {
		entry.NumSubmissionsSimError = 1
	}
	if isTopbid {
		entry.NumSubmissionsTopBid = 1
	}

	// Upsert
	query := `INSERT INTO ` + TableBlockBuilder + `
		(builder_pubkey, description, is_high_prio, is_blacklisted, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_submissions_topbid) VALUES
		(:builder_pubkey, :description, :is_high_prio, :is_blacklisted, :last_submission_id, :last_submission_slot, :num_submissions_total, :num_submissions_simerror, :num_submissions_topbid)
		ON CONFLICT (builder_pubkey) DO UPDATE SET
			last_submission_id = :last_submission_id,
			last_submission_slot = :last_submission_slot,
			num_submissions_total = ` + TableBlockBuilder + `.num_submissions_total + 1,
			num_submissions_simerror = ` + TableBlockBuilder + `.num_submissions_simerror + :num_submissions_simerror,
			num_submissions_topbid = ` + TableBlockBuilder + `.num_submissions_topbid + :num_submissions_topbid;`
	_, err := s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) GetBlockBuilders() ([]*BlockBuilderEntry, error) {
	query := `SELECT id, inserted_at, builder_pubkey, description, is_high_prio, is_blacklisted, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_submissions_topbid, num_sent_getpayload FROM ` + TableBlockBuilder + ` ORDER BY id ASC;`
	entries := []*BlockBuilderEntry{}
	err := s.DB.Select(entries, query)
	return entries, err
}

func (s *DatabaseService) GetBlockBuilderByPubkey(pubkey string) (*BlockBuilderEntry, error) {
	query := `SELECT id, inserted_at, builder_pubkey, description, is_high_prio, is_blacklisted, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_submissions_topbid, num_sent_getpayload FROM ` + TableBlockBuilder + ` WHERE builder_pubkey=$1;`
	entry := &BlockBuilderEntry{}
	err := s.DB.Get(entry, query, pubkey)
	return entry, err
}

func (s *DatabaseService) SetBlockBuilderStatus(pubkey string, isHighPrio, isBlacklisted bool) error {
	query := `UPDATE ` + TableBlockBuilder + ` SET is_high_prio=$1, is_blacklisted=$2 WHERE builder_pubkey=$3;`
	_, err := s.DB.Exec(query, isHighPrio, isBlacklisted, pubkey)
	return err
}

func (s *DatabaseService) IncBlockBuilderStatsAfterGetPayload(slot uint64, blockhash string) error {
	query := `UPDATE ` + TableBlockBuilder + `
		SET num_sent_getpayload=num_sent_getpayload+1
		FROM (
			SELECT builder_pubkey FROM ` + TableBuilderBlockSubmission + ` WHERE slot=$1 AND block_hash=$2
		) AS sub
		WHERE ` + TableBlockBuilder + `.builder_pubkey=sub.builder_pubkey;`
	_, err := s.DB.Exec(query, slot, blockhash)
	return err
}
