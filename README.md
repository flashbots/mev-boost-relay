# Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/boost-relay)](https://goreportcard.com/report/github.com/flashbots/boost-relay)
[![Test status](https://github.com/flashbots/boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/boost-relay/actions?query=workflow%3A%22Checks%22)

Flashbots [mev-boost](https://github.com/flashbots/mev-boost/) relay.

See also:

* https://www.notion.so/flashbots/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5#38a21c8a40e64970904500eb7b373ea5
* https://www.notion.so/flashbots/Relay-Design-Infra-APIs-cf5edd57360140668c6d6b78fd04f312

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

Visit adminer on http://localhost:8093/?username=postgres

The services need access to a beacon node for event subscriptions (by default using `localhost:3500` which is the Prysm default beacon-API port). You can proxy the port from a server like this:

```bash
ssh -L 3500:localhost:3500 fb-builder-kilndev
```

Now start the services:

```bash
# The housekeeper sets up the validators, and does various housekeeping
go run . housekeeper --network kiln --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run APIs for Kiln
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

Env vars:

* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests
* `ENABLE_ZERO_VALUE_BLOCKS` - allow blocks with 0 value
* `SYNC_VALIDATOR_REGISTRATIONS` - handle validator registrations synchronously instead of in a background worker pool
* `ALLOW_BLOCK_VERIFICATION_FAIL` - accept block even if block simulation fails