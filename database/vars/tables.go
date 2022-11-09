// Package vars contains the database variables such as dynamic table names
package vars

import "github.com/flashbots/mev-boost-relay/config"

var (
	tableBase = config.GetString(config.KeyDBTablePrefix)

	TableMigrations             = tableBase + "_migrations"
	TableValidatorRegistration  = tableBase + "_validator_registration"
	TableExecutionPayload       = tableBase + "_execution_payload"
	TableBuilderBlockSubmission = tableBase + "_builder_block_submission"
	TableDeliveredPayload       = tableBase + "_payload_delivered"
	TableBlockBuilder           = tableBase + "_blockbuilder"
)
