// Package migrations contains all the migration files
package migrations

import (
	migrate "github.com/rubenv/sql-migrate"
)

var migrations = []func() *migrate.Migration{
	GetInitDatabase,
}

func GetMigrations() *migrate.MemoryMigrationSource {
	m := make([]*migrate.Migration, len(migrations))
	for i := range migrations {
		m[i] = migrations[i]()
	}
	return &migrate.MemoryMigrationSource{
		Migrations: m,
	}
}
