package database

import (
	"time"
)

type ValidatorRegistrationEntry struct {
	ID                    uint64    `db:"id"`
	InsertedAt            time.Time `db:"inserted_at"`
	Pubkey                string    `db:"pubkey"`
	Registration          string    `db:"registration"`
	RegistrationTimestamp time.Time `db:"registration_timestamp"`
}
