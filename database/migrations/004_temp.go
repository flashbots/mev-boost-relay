package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration004Temp = &migrate.Migration{
	Id: "004-temp",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD submission_duration   bigint NOT NULL default 0;
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD optimistic_submission bool NOT NULL default false;
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
