module github.com/flashbots/mev-boost-relay

go 1.20

require (
	github.com/NYTimes/gziphandler v1.1.1
	github.com/alicebob/miniredis/v2 v2.31.0
	github.com/attestantio/go-builder-client v0.4.2
	github.com/attestantio/go-eth2-client v0.19.9
	github.com/bradfitz/gomemcache v0.0.0-20230124162541-5f7a7d875746
	github.com/btcsuite/btcd/btcutil v1.1.2
	github.com/buger/jsonparser v1.1.1
	github.com/ethereum/go-ethereum v1.13.10
	github.com/flashbots/go-boost-utils v1.8.0
	github.com/flashbots/go-utils v0.5.0
	github.com/go-redis/redis/v9 v9.0.0-rc.1
	github.com/gorilla/mux v1.8.1
	github.com/holiman/uint256 v1.2.4
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.8
	github.com/pkg/errors v0.9.1
	github.com/r3labs/sse/v2 v2.10.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.8.4
	github.com/tdewolff/minify v2.3.6+incompatible
	go.uber.org/atomic v1.11.0
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa
	golang.org/x/text v0.14.0
)

require (
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.12.1 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-playground/validator/v10 v10.11.1 // indirect
	github.com/goccy/go-yaml v1.11.2 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/prysmaticlabs/go-bitfield v0.0.0-20210809151128-385d8c5e3fb7 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

require (
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/btcsuite/btcd v0.23.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/ferranbt/fastssz v0.1.3
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rubenv/sql-migrate v1.5.2
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tdewolff/parse v2.3.4+incompatible // indirect
	github.com/tdewolff/test v1.0.7 // indirect
	github.com/yuin/gopher-lua v1.1.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.25.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/net v0.18.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	gopkg.in/cenkalti/backoff.v1 v1.1.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// https://go.dev/ref/mod#go-mod-file-retract
retract (
	v1.15.3
	v1.15.2
	v1.0.0-alpha4
	v1.0.0-alpha3
	v1.0.0-alpha2
	v1.0.0-alpha1
)
