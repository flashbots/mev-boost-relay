// Package database exposes the postgres database
package database

import (
	"encoding/json"
	"time"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

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
	// fmt.Println(schema)

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
	regStr, err := json.Marshal(registration)
	entry := ValidatorRegistrationEntry{
		Pubkey:                registration.Message.Pubkey.String(),
		Registration:          string(regStr),
		RegistrationTimestamp: time.Unix(int64(registration.Message.Timestamp), 0), // UTC
	}
	if err != nil {
		return err
	}

	query := `INSERT INTO ` + TableValidatorRegistration + ` (pubkey, registration, registration_timestamp) VALUES (:pubkey, :registration, :registration_timestamp) ON CONFLICT DO NOTHING`
	_, err = s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) SaveEpochSummary(summary common.EpochSummary) error {
	query := `INSERT INTO ` + TableEpochSummary + ` (epoch, slot_first, slot_last, slot_first_processed, slot_last_processed, validators_known_total, validator_registrations_total, validator_registrations_saved, validator_registrations_received_unverified, num_register_validator_requests, num_get_header_requests, num_get_payload_requests, num_header_sent_ok, num_header_sent_204, num_payload_sent, num_builder_bid_received, is_complete) VALUES (:epoch, :slot_first, :slot_last, :slot_first_processed, :slot_last_processed, :validators_known_total, :validator_registrations_total, :validator_registrations_saved, :validator_registrations_received_unverified, :num_register_validator_requests, :num_get_header_requests, :num_get_payload_requests, :num_header_sent_ok, :num_header_sent_204, :num_payload_sent, :num_builder_bid_received, :is_complete)`
	_, err := s.DB.NamedExec(query, summary)
	return err
}
