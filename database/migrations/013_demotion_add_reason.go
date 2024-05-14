package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration013DemotionAddHeaderSubmission = &migrate.Migration{
	Id: "013-demotion-add-header-submission",
	Up: []string{
		`
		ALTER TABLE ` + vars.TableBuilderDemotions + ` ADD reason text;
	`,
	},
	Down:                   []string{},
	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
