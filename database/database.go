// Package database exposes the postgres database
package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type IDatabaseService interface {
	SaveValidatorRegistration(registration types.SignedValidatorRegistration) error
	SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error) (id int64, err error)
	SaveDeliveredPayload(slot uint64, proposerPubkey types.PubkeyHex, blockHash types.Hash, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock) error

	GetBlockSubmissionEntry(slot uint64, proposerPubkey, blockHash string) (entry *BuilderBlockSubmissionEntry, err error)
	GetExecutionPayloadEntryByID(executionPayloadID int64) (entry *ExecutionPayloadEntry, err error)
	GetExecutionPayloadEntryBySlotPkHash(slot uint64, proposerPubkey, blockHash string) (entry *ExecutionPayloadEntry, err error)

	GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error)
	GetNumDeliveredPayloads() (uint64, error)
	GetBuilderSubmissions(filters GetBuilderSubmissionsFilters) ([]*BuilderBlockSubmissionEntry, error)
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

	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}

	return &DatabaseService{
		DB: db,
	}, nil
}

func (s *DatabaseService) Close() error {
	return s.DB.Close()
}

func (s *DatabaseService) SaveValidatorRegistration(registration types.SignedValidatorRegistration) error {
	entry := ValidatorRegistrationEntry{
		Pubkey:       registration.Message.Pubkey.String(),
		FeeRecipient: registration.Message.FeeRecipient.String(),
		Timestamp:    registration.Message.Timestamp,
		GasLimit:     registration.Message.GasLimit,
		Signature:    registration.Signature.String(),
	}

	// Check if we already have a registration with same or newer timestamp
	prevEntry := new(ValidatorRegistrationEntry)
	err := s.DB.Get(prevEntry, "SELECT pubkey, timestamp FROM "+TableValidatorRegistration+" WHERE pubkey = $1", entry.Pubkey)
	if errors.Is(err, sql.ErrNoRows) {
		// Insert new entry
		query := `INSERT INTO ` + TableValidatorRegistration + ` (pubkey, fee_recipient, timestamp, gas_limit, signature) VALUES (:pubkey, :fee_recipient, :timestamp, :gas_limit, :signature)`
		_, err = s.DB.NamedExec(query, entry)
		return err
	} else if err != nil {
		return err
	} else if entry.Timestamp > prevEntry.Timestamp {
		// Update
		query := `UPDATE ` + TableValidatorRegistration + ` SET fee_recipient=:fee_recipient, timestamp=:timestamp, gas_limit=:gas_limit, signature=:signature WHERE pubkey=:pubkey`
		_, err = s.DB.NamedExec(query, entry)
		return err
	}
	return nil
}

func (s *DatabaseService) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error) (id int64, err error) {
	// Save execution_payload: insert, or if already exists update to be able to return the id ('on conflict do nothing' doesn't return an id)
	execPayloadEntry, err := PayloadToExecPayloadEntry(payload)
	if err != nil {
		return 0, err
	}
	query := `INSERT INTO ` + TableExecutionPayload + `
	(slot, proposer_pubkey, block_hash, version, payload) VALUES
	(:slot, :proposer_pubkey, :block_hash, :version, :payload)
	ON CONFLICT (slot, proposer_pubkey, block_hash) DO UPDATE SET slot=:slot
	RETURNING id`
	nstmt, err := s.DB.PrepareNamed(query)
	if err != nil {
		return 0, err
	}
	err = nstmt.QueryRow(execPayloadEntry).Scan(&execPayloadEntry.ID)
	if err != nil {
		return 0, err
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

		Epoch:       payload.Message.Slot / uint64(common.SlotsPerEpoch),
		BlockNumber: payload.ExecutionPayload.BlockNumber,
	}
	query = `INSERT INTO ` + TableBuilderBlockSubmission + `
	(execution_payload_id, sim_success, sim_error, signature, slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value, epoch, block_number) VALUES
	(:execution_payload_id, :sim_success, :sim_error, :signature, :slot, :parent_hash, :block_hash, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :gas_used, :gas_limit, :num_tx, :value, :epoch, :block_number)
	RETURNING id`
	nstmt, err = s.DB.PrepareNamed(query)
	if err != nil {
		return 0, err
	}
	err = nstmt.QueryRow(blockSubmissionEntry).Scan(&blockSubmissionEntry.ID)
	if err != nil {
		return 0, err
	}

	return blockSubmissionEntry.ID, err
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

func (s *DatabaseService) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	arg := map[string]interface{}{
		"limit":        filters.Limit,
		"slot":         filters.Slot,
		"cursor":       filters.Cursor,
		"block_hash":   filters.BlockHash,
		"block_number": filters.BlockNumber,
	}

	tasks := []*DeliveredPayloadEntry{}
	fields := "id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"

	whereConds := []string{}
	if filters.Slot > 0 {
		whereConds = append(whereConds, "slot = :slot")
	} else if filters.Cursor > 0 {
		whereConds = append(whereConds, "slot <= :cursor")
	}
	if filters.BlockHash != "" {
		whereConds = append(whereConds, "block_hash = :block_hash")
	}
	if filters.BlockNumber > 0 {
		whereConds = append(whereConds, "block_number = :block_number")
	}

	where := ""
	if len(whereConds) > 0 {
		where = "WHERE " + strings.Join(whereConds, " AND ")
	}

	nstmt, err := s.DB.PrepareNamed(fmt.Sprintf("SELECT %s FROM %s %s ORDER BY id DESC LIMIT :limit", fields, TableDeliveredPayload, where))
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
		"limit":        filters.Limit,
		"slot":         filters.Slot,
		"cursor":       filters.Cursor,
		"block_hash":   filters.BlockHash,
		"block_number": filters.BlockNumber,
	}

	tasks := []*BuilderBlockSubmissionEntry{}
	fields := "id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"

	whereConds := []string{"sim_success = true"}
	if filters.Slot > 0 {
		whereConds = append(whereConds, "slot = :slot")
	} else if filters.Cursor > 0 {
		whereConds = append(whereConds, "slot <= :cursor")
	}
	if filters.BlockHash != "" {
		whereConds = append(whereConds, "block_hash = :block_hash")
	}
	if filters.BlockNumber > 0 {
		whereConds = append(whereConds, "block_number = :block_number")
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
