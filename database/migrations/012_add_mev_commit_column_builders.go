package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration012AddMevCommitColumnBuilders = &migrate.Migration{
	Id: "012-add-mev-commit-column-builders",
	Up: []string{`
		ALTER TABLE ` + vars.TableBlockBuilder + ` ADD is_mev_commit_enabled boolean NOT NULL DEFAULT false;
	`},
	Down: []string{`
		ALTER TABLE ` + vars.TableBlockBuilder + ` DROP COLUMN is_mev_commit_enabled;
	`},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
