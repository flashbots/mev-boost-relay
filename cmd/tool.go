package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/spf13/cobra"
)

var (
	toolOutfile string
	idFirst     uint64
	idLast      uint64
	dateStart   string
	dateEnd     string
)

func init() {
	toolDataAPIExportPayloads.Flags().StringVar(&toolOutfile, "out", "", "output filename")
	toolDataAPIExportPayloads.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	toolDataAPIExportPayloads.Flags().Uint64Var(&idFirst, "id-from", 0, "start id (inclusive")
	toolDataAPIExportPayloads.Flags().Uint64Var(&idLast, "id-to", 0, "end id (inclusive)")
	toolDataAPIExportPayloads.Flags().StringVar(&dateStart, "date-start", "", "start date (inclusive)")
	toolDataAPIExportPayloads.Flags().StringVar(&dateEnd, "date-end", "", "end date (exclusive)")
	_ = toolDataAPIExportPayloads.MarkFlagRequired("out")

	toolCmd.AddCommand(toolDataAPIExportPayloads)
	rootCmd.AddCommand(toolCmd)
}

var log = common.LogSetup(false, "info")

var toolCmd = &cobra.Command{
	Use: "tool",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Error: please use a valid subcommand")
		_ = cmd.Help()
	},
}

var toolDataAPIExportPayloads = &cobra.Command{
	Use: "data-api-export-payloads",
	Run: func(cmd *cobra.Command, args []string) {
		if toolOutfile == "" {
			log.Fatal("no output file specified")
		}
		log.Infof("exporting data-api payloads to %s", toolOutfile)

		if (idFirst == 0 && dateStart == "") || (idLast == 0 && dateEnd == "") {
			log.Fatal("must specify start and end id or date")
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
			query := `SELECT id FROM ` + database.TableDeliveredPayload + ` WHERE inserted_at::date >= date '` + dateStart + `' ORDER BY id ASC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idFirst)
			if err != nil {
				log.WithError(err).Fatalf("failed to find start id for date %s", dateStart)
			}
		}
		if dateEnd != "" {
			// find last enry before dateEnd
			query := `SELECT id FROM ` + database.TableDeliveredPayload + ` WHERE inserted_at::date < date '` + dateEnd + `' ORDER BY id DESC LIMIT 1;`
			err = db.DB.QueryRow(query).Scan(&idLast)
			if err != nil {
				log.WithError(err).Fatalf("failed to find end id for date %s", dateEnd)
			}
		}
		log.Infof("exporting ids %d to %d", idFirst, idLast)

		deliveredPayloads, err := db.GetDeliveredPayloads(idFirst, idLast)
		if err != nil {
			log.WithError(err).Fatal("error getting recent payloads")
		}

		log.Infof("got %d payloads", len(deliveredPayloads))
		entries := make([]common.BidTraceJSON, len(deliveredPayloads))
		for i, payload := range deliveredPayloads {
			entries[i] = database.DeliveredPayloadEntryToBidTraceJSON(payload)
		}

		if len(entries) == 0 {
			return
		}

		f, err := os.Create(toolOutfile)
		if err != nil {
			log.WithError(err).Fatal("failed to open file")
		}
		defer f.Close()

		if strings.HasSuffix(toolOutfile, ".csv") {
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
		log.Infof("Wrote %d entries to %s", len(entries), toolOutfile)
	},
}
