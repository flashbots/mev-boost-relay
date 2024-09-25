package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration013AddMevCommitValidatorsTable = &migrate.Migration{
	Id: "013-add-mev-commit-validators-table",
	Up: []string{`
		CREATE TABLE IF NOT EXISTS ` + vars.TableMevCommitValidators + ` (
			id SERIAL PRIMARY KEY,
			pubkey VARCHAR(98) NOT NULL,
			is_opted_in BOOLEAN NOT NULL DEFAULT false,
			timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`},
	Down: []string{`
		DROP TABLE mev_commit_validator_registration;
	`},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
