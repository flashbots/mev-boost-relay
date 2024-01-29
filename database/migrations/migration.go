// Package migrations contains all the migration files
package migrations

import (
	migrate "github.com/rubenv/sql-migrate"
)

var Migrations = migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		Migration001InitDatabase,
		Migration002RemoveIsBestAddReceivedAt,
		Migration003AddEligibleAtSignedAt,
		Migration004BlockedValidator,
		Migration005RemoveBlockedValidator,
		Migration006CreateTooLateGetPayload,
		Migration007BuilderSubmissionWasSimulated,
		Migration008Optimistic,
		Migration009BlockBuilderRemoveReference,
		Migration010PayloadAddBlobFields,
	},
}
