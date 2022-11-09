package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration002RemoveIsBestAddReceivedAt = &migrate.Migration{
	Id: "002-remove-isbest-add-receivedat",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD received_at timestamp;

		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` DROP COLUMN was_most_profitable;
		DROP INDEX IF EXISTS ` + vars.TableBuilderBlockSubmission + `_mostprofit_idx;

		ALTER TABLE ` + vars.TableBlockBuilder + ` DROP COLUMN num_submissions_topbid;
	`, `
		CREATE INDEX CONCURRENTLY IF NOT EXISTS ` + vars.TableBuilderBlockSubmission + `_received_idx ON ` + vars.TableBuilderBlockSubmission + `(received_at DESC);
	`},
	Down: []string{},

	DisableTransactionUp:   true, // cannot create index concurrently inside a transaction
	DisableTransactionDown: true,
}
