// Package migrations contains all the migration files
package migrations

import (
	migrate "github.com/rubenv/sql-migrate"
)

var migrations = []*migrate.Migration{
	GetInitDatabase,
}

func GetMigrations() *migrate.MemoryMigrationSource {
	m := make([]*migrate.Migration, len(migrations))
	copy(m, migrations)
	return &migrate.MemoryMigrationSource{
		Migrations: m,
	}
}
