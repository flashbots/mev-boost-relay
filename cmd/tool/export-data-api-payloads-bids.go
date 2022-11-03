package tool

import (
	"encoding/csv"
	"encoding/json"
	"net/url"
	"os"
	"strings"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/spf13/cobra"
)

func init() {
	DataAPIExportBids.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	DataAPIExportBids.Flags().Uint64Var(&idFirst, "id-from", 0, "start id (inclusive")
	DataAPIExportBids.Flags().Uint64Var(&idLast, "id-to", 0, "end id (inclusive)")
	DataAPIExportBids.Flags().StringVar(&dateStart, "date-start", "", "start date (inclusive)")
	DataAPIExportBids.Flags().StringVar(&dateEnd, "date-end", "", "end date (exclusive)")
	DataAPIExportBids.Flags().StringSliceVar(&outFiles, "out", []string{}, "output filename")
	_ = DataAPIExportBids.MarkFlagRequired("out")
}

var DataAPIExportBids = &cobra.Command{
	Use: "data-api-export-bids",
	Run: func(cmd *cobra.Command, args []string) {
		if len(outFiles) == 0 {
			log.Fatal("no output files specified")
		}
		log.Infof("exporting data-api bods to %s", strings.Join(outFiles, ", "))

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
			query := `SELECT id FROM ` + database.TableBuilderBlockSubmission + ` WHERE inserted_at::date >= date '` + dateStart + `' ORDER BY id ASC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idFirst)
			if err != nil {
				log.WithError(err).Fatalf("failed to find start id for date %s", dateStart)
			}
		}
		if dateEnd != "" {
			// find last entry before dateEnd
			query := `SELECT id FROM ` + database.TableBuilderBlockSubmission + ` WHERE inserted_at::date < date '` + dateEnd + `' ORDER BY id DESC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idLast)
			if err != nil {
				log.WithError(err).Fatalf("failed to find end id for date %s", dateEnd)
			}
		}
		log.Infof("exporting ids %d to %d", idFirst, idLast)

		bids, err := db.GetBuilderSubmissionsByID(idFirst, idLast)
		if err != nil {
			log.WithError(err).Fatal("error getting recent payloads")
		}

		log.Infof("got %d bids", len(bids))
		entries := make([]common.BidTraceV2WithTimestampJSON, len(bids))
		for i, bid := range bids {
			entries[i] = database.BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(bid)
		}

		if len(entries) == 0 {
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
				if err := w.Write(entries[0].CSVHeader()); err != nil {
					log.WithError(err).Fatal("error writing record to file")
				}
				for _, record := range entries {
					if err := w.Write(record.ToCSVRecord()); err != nil {
						log.WithError(err).Fatal("error writing record to file")
					}
				}
			} else {
				// write JSON
				encoder := json.NewEncoder(f)
				err = encoder.Encode(entries)
				if err != nil {
					log.WithError(err).Fatal("failed to write json to file")
				}
			}
			log.Infof("Wrote %d entries to %s", len(entries), outFile)
		}

		for _, outFile := range outFiles {
			writeToFile(outFile)
		}
	},
}
