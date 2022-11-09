package tool

import (
	"net/url"

	"github.com/flashbots/mev-boost-relay/database/migrations"
	"github.com/flashbots/mev-boost-relay/database/vars"
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/spf13/cobra"
)

func init() {
	Migrate.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
}

var Migrate = &cobra.Command{
	Use:   "migrate",
	Short: "migrate the database to the latest schema",
	Run: func(cmd *cobra.Command, args []string) {
		// Connect to Postgres
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := sqlx.Connect("postgres", postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		log.Infof("Migrating database ...")
		migrate.SetTable(vars.TableMigrations)
		numAppliedMigrations, err := migrate.Exec(db.DB, "postgres", migrations.Migrations, migrate.Up)
		if err != nil {
			log.WithError(err).Fatalf("Failed to migrate database")
		}
		log.WithField("num_applied_migrations", numAppliedMigrations).Info("Migrations applied successfully")
	},
}
