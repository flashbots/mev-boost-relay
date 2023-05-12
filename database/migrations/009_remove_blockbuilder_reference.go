package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

// Migration009BlockBuilderRemoveReference removes the foreign key constraint from
// the blockbuilders table to the latest submissions by a builder.
//
// This reference makes it impossible to migrate to a new database without having
// all bids there first (which is the bulk of the data). Just removing the foreign key
// constraint is the easiest way to solve this constraint, without downsides.
var Migration009BlockBuilderRemoveReference = &migrate.Migration{
	Id: "009-block-builder-remove-reference",
	Up: []string{`
		ALTER TABLE ` + vars.TableBlockBuilder + ` DROP CONSTRAINT "` + vars.TableBlockBuilder + `_last_submission_id_fkey";
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
