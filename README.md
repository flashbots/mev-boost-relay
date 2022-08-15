# Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/boost-relay)](https://goreportcard.com/report/github.com/flashbots/boost-relay)
[![Test status](https://github.com/flashbots/boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/boost-relay/actions?query=workflow%3A%22Checks%22)

Flashbots [mev-boost](https://github.com/flashbots/mev-boost/) relay, as running for [Goerli](https://builder-relay-goerli.flashbots.net/) and the other test networks.

Provides the builder-specs API for Eth2 validators, an API for block builders to submit blocks, as well as a data API.

The relay software is currently in **alpha state**, and there'll be significant changes in the following weeks. In particular major database schema changes, decoupling of block submissions from the proposer API and proper expiy of Redis entries.

See also:

* [Relay API Spec](https://flashbots.notion.site/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5)
* [builder-relay-goerli.flashbots.net](https://builder-relay-goerli.flashbots.net/)

---

The relay consists of several components that are designed to run and scale independently and to be as simple as possible:

1. Housekeeper: update known validators, proposer duties. Soon: save metrics, etc.
2. API: for proposer, block builder, data
3. Website: handles the root website requests (information is pulled from Redis and database)

## Getting started

Redis (v6+) and PostgreSQL is used.

```bash
# Start PostgreSQL & Redis in Docker
docker-compose up
```

(you can now visit adminer on http://localhost:8093/?username=postgres)

The services need access to a beacon node for event subscriptions and the beacon API (by default using `localhost:3500` which is the Prysm default beacon-API port). You can proxy the port from a server like this:

```bash
ssh -L 3500:localhost:3500 your_server
```

Now start the services:

```bash
# The housekeeper sets up the validators, and does various housekeeping
go run . housekeeper --network kiln --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run APIs for Kiln (using a dummy BLS secret key)
go run . api --network kiln --secret-key 0x607a11b45a7219cc61a3d9c5fd08c7eebd602a6a19a977f8d3771d5711a550f2 --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run Website for Kiln
go run . website --network kiln --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Query status
curl localhost:9062/eth/v1/builder/status

# Send test validator registrations
curl -X POST localhost:9062/eth/v1/builder/validators -d @testdata/valreg2.json

# Delete previous registrations
redis-cli DEL boost-relay/kiln:validators-registration boost-relay/kiln:validators-registration-timestamp
```

---

Run tests and linter:

```bash
make test
make test-race
make lint
```

---

Env vars:

* `DB_TABLE_PREFIX` - prefix to use for db tables (default uses `dev`)
* `ENABLE_ZERO_VALUE_BLOCKS` - allow blocks with 0 value
* `SYNC_VALIDATOR_REGISTRATIONS` - handle validator registrations synchronously instead of in a background worker pool
* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests
* `ALLOW_BLOCK_VERIFICATION_FAIL` - accept block even if block simulation & verification fails
* `DISABLE_BID_MEMORY_CACHE` - force bids to go through redis/db
