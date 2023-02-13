package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration005Profiling = &migrate.Migration{
	Id: "005-profiling",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD precheck_duration       bigint NOT NULL default 0;
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD simulation_duration     bigint NOT NULL default 0;
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD redis_update_duration   bigint NOT NULL default 0;
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
