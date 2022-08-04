// Package database exposes the postgres database
package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type IDatabaseService interface {
	SaveValidatorRegistration(registration types.SignedValidatorRegistration) error
	SaveDeliveredPayload(entry *DeliveredPayloadEntry) error
	SaveBuilderBlockSubmission(entry *BuilderBlockEntry) error
	GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error)
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

func (s *DatabaseService) Close() {
	s.DB.Close()
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
	if err == sql.ErrNoRows {
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

// func (s *DatabaseService) SaveEpochSummary(summary common.EpochSummary) error {
// 	query := `INSERT INTO ` + TableEpochSummary + ` (epoch, slot_first, slot_last, slot_first_processed, slot_last_processed, validators_known_total, validator_registrations_total, validator_registrations_saved, validator_registrations_received_unverified, num_register_validator_requests, num_get_header_requests, num_get_payload_requests, num_header_sent_ok, num_header_sent_204, num_payload_sent, num_builder_bid_received, is_complete) VALUES (:epoch, :slot_first, :slot_last, :slot_first_processed, :slot_last_processed, :validators_known_total, :validator_registrations_total, :validator_registrations_saved, :validator_registrations_received_unverified, :num_register_validator_requests, :num_get_header_requests, :num_get_payload_requests, :num_header_sent_ok, :num_header_sent_204, :num_payload_sent, :num_builder_bid_received, :is_complete)`
// 	_, err := s.DB.NamedExec(query, summary)
// 	return err
// }

func (s *DatabaseService) SaveDeliveredPayload(entry *DeliveredPayloadEntry) error {
	query := `INSERT INTO ` + TableDeliveredPayload + ` (epoch, slot, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit, execution_payload, bid_trace, bid_trace_builder_sig, signed_builder_bid, signed_blinded_beacon_block) VALUES (:epoch, :slot, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :num_tx, :value, :gas_used, :gas_limit, :execution_payload, :bid_trace, :bid_trace_builder_sig, :signed_builder_bid, :signed_blinded_beacon_block) ON CONFLICT DO NOTHING`
	_, err := s.DB.NamedExec(query, entry)
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
	if filters.IncludePayloads {
		fields += ", execution_payload, bid_trace, bid_trace_builder_sig, signed_builder_bid, signed_blinded_beacon_block"
	} else if filters.IncludeBidTrace {
		fields += ", bid_trace, bid_trace_builder_sig"
	}

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

	// fmt.Println("nstmt", nstmt.QueryString)
	err = nstmt.Select(&tasks, arg)
	return tasks, err
}

func (s *DatabaseService) GetNumDeliveredPayloads() (uint64, error) {
	var count uint64
	err := s.DB.QueryRow("SELECT COUNT(*) FROM " + TableDeliveredPayload).Scan(&count)
	return count, err
}

func (s *DatabaseService) SaveBuilderBlockSubmission(entry *BuilderBlockEntry) error {
	query := `INSERT INTO ` + TableBuilderBlockSubmission + ` (epoch, slot, builder_pubkey, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, num_tx, value, gas_used, gas_limit, payload, sim_success, sim_error) VALUES (:epoch, :slot, :builder_pubkey, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :num_tx, :value, :gas_used, :gas_limit, :payload, :sim_success, :sim_error) RETURNING id`
	_, err := s.DB.NamedExec(query, entry)
	return err
}
