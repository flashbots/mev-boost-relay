package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration003AddEligibleAtSignedAt = &migrate.Migration{
	Id: "003-add-eligibleat-add-signedat",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD eligible_at timestamp;
		ALTER TABLE ` + vars.TableDeliveredPayload + ` ADD signed_at timestamp;
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
