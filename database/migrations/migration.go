// Package migrations contains all the migration files
package migrations

import (
	migrate "github.com/rubenv/sql-migrate"
)

var migrations = []*migrate.Migration{
	Migration001InitDatabase,
}

func GetMigrations() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: migrations,
	}
}
