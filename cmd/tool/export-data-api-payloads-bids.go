package tool

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/spf13/cobra"
)

var (
	slotFrom uint64
	slotTo   uint64
)

func init() {
	DataAPIExportBids.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	DataAPIExportBids.Flags().Uint64Var(&slotFrom, "slot-from", 0, "start slot (inclusive")
	DataAPIExportBids.Flags().Uint64Var(&slotTo, "slot-to", 0, "end slot (inclusive)")
	DataAPIExportBids.Flags().StringSliceVar(&outFiles, "out", []string{}, "output filename")
}

var DataAPIExportBids = &cobra.Command{
	Use: "data-api-export-bids",
	Run: func(cmd *cobra.Command, args []string) {
		if len(outFiles) == 0 {
			outFnBase := fmt.Sprintf("builder-submissions_slot-%d-to-%d", slotFrom, slotTo)
			outFiles = append(outFiles, outFnBase+".csv")
			outFiles = append(outFiles, outFnBase+".json")
		}
		log.Infof("exporting data-api bids to %s", strings.Join(outFiles, ", "))

		if slotFrom == 0 || slotTo == 0 {
			log.Fatal("must specify --slot-from and --slot-to")
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

		log.Info("Connected to Postgres database, starting queries")
		log.Infof("exporting slots %d to %d (%d slots in total)...", slotFrom, slotTo, slotTo-slotFrom+1)

		bids, err := db.GetBuilderSubmissionsBySlots(slotFrom, slotTo)
		if err != nil {
			log.WithError(err).Fatal("failed getting bids")
		}

		log.Infof("got %d bids", len(bids))
		entries := make([]common.BidTraceV2WithTimestampJSON, len(bids))
		for i, bid := range bids {
			entries[i] = database.BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(bid)
		}

		if len(entries) == 0 {
			return
		}

		// Free up some memory
		bids = nil //nolint:ineffassign
		runtime.GC()

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
			runtime.GC()
		}

		for _, outFile := range outFiles {
			writeToFile(outFile)
		}
	},
}
