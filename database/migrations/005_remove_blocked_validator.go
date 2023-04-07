package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration005RemoveBlockedValidator = &migrate.Migration{
	Id: "005-remove-blocked-validator",
	Up: []string{`
		DROP TABLE IF EXISTS ` + vars.TableBlockedValidator + `;
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
