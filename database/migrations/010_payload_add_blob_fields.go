package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

// Migration010PayloadAddBlobFields adds blob related fields for the Dencun fork
// such as the number of blobs, blob gas used and excess blob gas
var Migration010PayloadAddBlobFields = &migrate.Migration{
	Id: "010-payload-add-blob-fields",
	Up: []string{`
		ALTER TABLE ` + vars.TableDeliveredPayload + ` ADD blob_gas_used bigint NOT NULL DEFAULT 0;
		ALTER TABLE ` + vars.TableDeliveredPayload + ` ADD excess_blob_gas bigint NOT NULL DEFAULT 0;
		ALTER TABLE ` + vars.TableDeliveredPayload + ` ADD num_blobs int NOT NULL DEFAULT 0;
	`},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
