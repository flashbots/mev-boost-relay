package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration012OptimisticSubmissionTable = &migrate.Migration{
	Id: "012-optimistic-submission-table",
	Up: []string{`
		CREATE TABLE IF NOT EXISTS ` + vars.TableBuilderOptimisticSubmission + ` (
			inserted_at timestamp NOT NULL default current_timestamp,

			block_hash 		varchar(66) PRIMARY KEY,
			slot       		bigint NOT NULL,
			builder_pubkey 	varchar(98) NOT NULL,
			proposer_pubkey varchar(98) NOT NULL,

			value 			bigint NOT NULL,
			fee_recipient 	varchar(98) NOT NULL,

			header_received_at 	timestamp,
			payload_received_at timestamp
		);
	`},
	Down: []string{`
		DROP TABLE IF EXISTS ` + vars.TableBuilderOptimisticSubmission + `;
	`},
	DisableTransactionUp:   false,
	DisableTransactionDown: false,
}
