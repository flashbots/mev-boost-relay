package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration013AddMevCommitColumnValidators = &migrate.Migration{
	Id: "013-add-mev-commit-column-validators",
	Up: []string{`
		ALTER TABLE ` + vars.TableValidatorRegistration + ` ADD is_mev_commit_opted_in boolean NOT NULL DEFAULT false;
	`},
	Down: []string{`
		ALTER TABLE ` + vars.TableValidatorRegistration + ` DROP COLUMN is_mev_commit_opted_in;
	`},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
