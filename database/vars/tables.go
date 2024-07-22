// Package vars contains the database variables such as dynamic table names
package vars

import "github.com/flashbots/mev-boost-relay/common"

var (
	tableBase = common.GetEnv("DB_TABLE_PREFIX", "dev")

	TableMigrations             = "migrations"
	TableValidatorRegistration  = "validator_registration"
	TableExecutionPayload       = "execution_payload"
	TableBuilderBlockSubmission = "block_submission"
	TableDeliveredPayload       = "payload_delivered"
	TableBlockBuilder           = "builder"
	TableBuilderDemotions       = "builder_demotions"
	TableBlockedValidator       = "blocked_validator"
	TableTooLateGetPayload      = "too_late_get_payload"
)
