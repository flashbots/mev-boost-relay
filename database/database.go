// Package database exposes the postgres database
package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type IDatabaseService interface {
	SaveValidatorRegistration(registration types.SignedValidatorRegistration) error
	// SaveDeliveredPayload(entry *DeliveredPayloadEntry) error
	SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error) error
	// GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error)
	GetNumDeliveredPayloads() (uint64, error)
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

// func (s *DatabaseService) SaveDeliveredPayload(entry *DeliveredPayloadEntry) error {
// 	query := `INSERT INTO ` + TableDeliveredPayload + ` (epoch, slot, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit, execution_payload, bid_trace, bid_trace_builder_sig, signed_builder_bid, signed_blinded_beacon_block) VALUES (:epoch, :slot, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :num_tx, :value, :gas_used, :gas_limit, :execution_payload, :bid_trace, :bid_trace_builder_sig, :signed_builder_bid, :signed_blinded_beacon_block) ON CONFLICT DO NOTHING`
// 	_, err := s.DB.NamedExec(query, entry)
// 	return err
// }

// func (s *DatabaseService) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
// 	arg := map[string]interface{}{
// 		"limit":        filters.Limit,
// 		"slot":         filters.Slot,
// 		"cursor":       filters.Cursor,
// 		"block_hash":   filters.BlockHash,
// 		"block_number": filters.BlockNumber,
// 	}

// 	tasks := []*DeliveredPayloadEntry{}
// 	fields := "id, inserted_at, slot, epoch, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit"
// 	if filters.IncludePayloads {
// 		fields += ", execution_payload, bid_trace, bid_trace_builder_sig, signed_builder_bid, signed_blinded_beacon_block"
// 	} else if filters.IncludeBidTrace {
// 		fields += ", bid_trace, bid_trace_builder_sig"
// 	}

// 	whereConds := []string{}
// 	if filters.Slot > 0 {
// 		whereConds = append(whereConds, "slot = :slot")
// 	} else if filters.Cursor > 0 {
// 		whereConds = append(whereConds, "slot <= :cursor")
// 	}
// 	if filters.BlockHash != "" {
// 		whereConds = append(whereConds, "block_hash = :block_hash")
// 	}
// 	if filters.BlockNumber > 0 {
// 		whereConds = append(whereConds, "block_number = :block_number")
// 	}

// 	where := ""
// 	if len(whereConds) > 0 {
// 		where = "WHERE " + strings.Join(whereConds, " AND ")
// 	}

// 	nstmt, err := s.DB.PrepareNamed(fmt.Sprintf("SELECT %s FROM %s %s ORDER BY id DESC LIMIT :limit", fields, TableDeliveredPayload, where))
// 	if err != nil {
// 		return nil, err
// 	}

// 	err = nstmt.Select(&tasks, arg)
// 	return tasks, err
// }

func (s *DatabaseService) GetNumDeliveredPayloads() (uint64, error) {
	var count uint64
	err := s.DB.QueryRow("SELECT COUNT(*) FROM " + TableDeliveredPayload).Scan(&count)
	return count, err
}

func (s *DatabaseService) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest, simError error) error {
	// Save bid_trace
	bidTraceEntry := PayloadToBidTraceEntry(payload)
	query := `INSERT INTO ` + TableBidTrace + `(slot, parent_hash, block_hash, builder_pubkey, proposer_pubkey, proposer_fee_recipient, gas_used, gas_limit, num_tx, value) VALUES (:slot, :parent_hash, :block_hash, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :gas_used, :gas_limit, :num_tx, :value) RETURNING id`
	nstmt, err := s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}
	err = nstmt.QueryRow(bidTraceEntry).Scan(&bidTraceEntry.ID)
	if err != nil {
		return err
	}

	// Save execution_payload
	execPayloadEntry, err := PayloadToExecPayloadEntry(payload)
	if err != nil {
		return err
	}
	query = `INSERT INTO ` + TableExecutionPayload + `(slot, proposer_pubkey, block_hash, version, payload) VALUES (:slot, :proposer_pubkey, :block_hash, :version, :payload) RETURNING id`
	nstmt, err = s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}
	err = nstmt.QueryRow(execPayloadEntry).Scan(&execPayloadEntry.ID)
	if err != nil {
		return err
	}

	// Save block_submission
	simErrStr := ""
	if simError != nil {
		simErrStr = simError.Error()
	}

	blockSubmissionEntry := &BuilderBlockSubmissionEntry{
		Signature:          payload.Signature.String(),
		BidTraceID:         bidTraceEntry.ID,
		ExecutionPayloadID: execPayloadEntry.ID,

		SimSuccess: simError == nil,
		SimError:   simErrStr,

		Slot:  payload.Message.Slot,
		Epoch: payload.Message.Slot / uint64(common.SlotsPerEpoch),

		NumTx: bidTraceEntry.NumTx,
		Value: bidTraceEntry.Value,

		BlockNumber:   payload.ExecutionPayload.BlockNumber,
		BlockHash:     payload.ExecutionPayload.BlockHash.String(),
		ParentHash:    payload.ExecutionPayload.ParentHash.String(),
		BuilderPubkey: payload.Message.BuilderPubkey.String(),
	}
	query = `INSERT INTO ` + TableBuilderBlockSubmission + ` (signature, bid_trace_id, execution_payload_id, sim_success, sim_error, slot, epoch, num_tx, value, block_number, block_hash, parent_hash, builder_pubkey) VALUES (:signature, :bid_trace_id, :execution_payload_id, :sim_success, :sim_error, :slot, :epoch, :num_tx, :value, :block_number, :block_hash, :parent_hash, :builder_pubkey)`
	_, err = s.DB.NamedExec(query, blockSubmissionEntry)
	return err
}
