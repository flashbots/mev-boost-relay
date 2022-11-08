package tool

import (
	"encoding/csv"
	"encoding/json"
	"net/url"
	"os"
	"strings"

	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/database/vars"
	"github.com/spf13/cobra"
)

var doDelete bool

func init() {
	ArchiveExecutionPayloads.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	ArchiveExecutionPayloads.Flags().Uint64Var(&idFirst, "id-from", 0, "start id (inclusive")
	ArchiveExecutionPayloads.Flags().Uint64Var(&idLast, "id-to", 0, "end id (inclusive)")
	ArchiveExecutionPayloads.Flags().StringVar(&dateStart, "date-start", "", "start date (inclusive)")
	ArchiveExecutionPayloads.Flags().StringVar(&dateEnd, "date-end", "", "end date (exclusive)")
	ArchiveExecutionPayloads.Flags().BoolVar(&doDelete, "delete", false, "whether to also delete the archived payloads in the DB")
	ArchiveExecutionPayloads.Flags().StringSliceVar(&outFiles, "out", []string{}, "output filename")
	_ = ArchiveExecutionPayloads.MarkFlagRequired("out")
}

var ArchiveExecutionPayloads = &cobra.Command{
	Use:   "archive-execution-payloads",
	Short: "export execution payloads from the DB to a CSV or JSON file and archive by deleting the payloads",
	Run: func(cmd *cobra.Command, args []string) {
		if len(outFiles) == 0 {
			log.Fatal("no output files specified")
		}
		log.Infof("exporting execution payloads to %s", strings.Join(outFiles, ", "))

		if idLast == 0 && dateEnd == "" {
			log.Fatal("must specify --id-to or --date-end")
		}

		// Connect to Postgres
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		// if date, then find corresponding id
		if dateStart != "" {
			// find first enrty at or after dateStart
			query := `SELECT id FROM ` + vars.TableExecutionPayload + ` WHERE inserted_at::date >= date '` + dateStart + `' ORDER BY id ASC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idFirst)
			if err != nil {
				log.WithError(err).Fatalf("failed to find start id for date %s", dateStart)
			}
		}
		if dateEnd != "" {
			// find last enry before dateEnd
			query := `SELECT id FROM ` + vars.TableExecutionPayload + ` WHERE inserted_at::date < date '` + dateEnd + `' ORDER BY id DESC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idLast)
			if err != nil {
				log.WithError(err).Fatalf("failed to find end id for date %s", dateEnd)
			}
		}
		log.Infof("exporting ids %d to %d", idFirst, idLast)

		deliveredPayloads, err := db.GetExecutionPayloads(idFirst, idLast)
		if err != nil {
			log.WithError(err).Fatal("error getting execution payloads")
		}

		log.Infof("got %d payloads", len(deliveredPayloads))
		if len(deliveredPayloads) == 0 {
			return
		}

		writeToFile := func(outFile string) {
			f, err := os.Create(outFile)
			if err != nil {
				log.WithError(err).Fatal("failed to open file")
			}
			defer f.Close()

			if strings.HasSuffix(outFile, ".csv") {
				// write CSV
				w := csv.NewWriter(f)
				defer w.Flush()
				if err := w.Write(database.ExecutionPayloadEntryCSVHeader); err != nil {
					log.WithError(err).Fatal("error writing record to file")
				}
				for _, record := range deliveredPayloads {
					if err := w.Write(record.ToCSVRecord()); err != nil {
						log.WithError(err).Fatal("error writing record to file")
					}
				}
			} else {
				// write JSON
				encoder := json.NewEncoder(f)
				err = encoder.Encode(deliveredPayloads)
				if err != nil {
					log.WithError(err).Fatal("failed to write json to file")
				}
			}
			log.Infof("Wrote %d entries to %s", len(deliveredPayloads), outFile)
		}

		for _, outFile := range outFiles {
			writeToFile(outFile)
		}

		if doDelete {
			log.Infof("deleting archived payloads from DB")
			err = db.DeleteExecutionPayloads(idFirst, idLast)
			if err != nil {
				log.WithError(err).Fatal("error deleting execution payloads")
			}
		}

		log.Infof("all done")
	},
}
