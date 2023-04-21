package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration007BuilderSubmissionWasSimulated = &migrate.Migration{
	Id: "007-builder-submission-was-simulated",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD was_simulated boolean NOT NULL DEFAULT true;
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD sim_req_error text NOT NULL DEFAULT '';
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
