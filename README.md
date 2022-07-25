# Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/boost-relay)](https://goreportcard.com/report/github.com/flashbots/boost-relay)
[![Test status](https://github.com/flashbots/boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/boost-relay/actions?query=workflow%3A%22Checks%22)

Flashbots internal PBS/[mev-boost](https://github.com/flashbots/mev-boost/) relay.

* Exposes a Builder REST API for mev-boost (proposer-api, conforming with [builder-specs](https://ethereum.github.io/builder-specs/#/Builder))
* Exposes an API for builders to send blocks (builder-api)

More information:

* https://www.notion.so/flashbots/Relay-API-Brainstorms-cf5edd57360140668c6d6b78fd04f312
* https://www.notion.so/flashbots/Relay-Design-Docs-623487c51b92423fabeb8da9c54af7f4

---

The relay consists of several components that are designed to run and scale independently and to be as simple as possible:

* API (proposer & builder): accept requests from proposers and builders
* Website: handles the root website requests (most of the information is pulled from Redis)
* Housekeeping: various updates, saves metrics, etc

## Getting started

Redis (v6+) is used to store known validators and validator registrations. You can start Redis with Docker like this:

```bash
docker run --name redis -d -p 6379:6379 redis:7
```

Postgres is optional:

```bash
#docker run --name postgres -e POSTGRES_PASSWORD=postgres -d -p 5432:5432 postgres
docker-compose up
```

Visit adminer on http://localhost:8093/?username=postgres

---

The API needs access to a beacon node for event subscriptions (by default using `localhost:3500` which is the Prysm default beacon-API port). You can proxy the port from a server like this:

```bash
ssh -L 3500:localhost:3500 fb-builder-kilndev
```

Run the API for Kiln (and update known validators first):

```bash
# Sync known validators from BN to Redis
go run . known-validator-update --kiln

# Run APIs for Kiln
go run . api --kiln --secret-key 0x607a11b45a7219cc61a3d9c5fd08c7eebd602a6a19a977f8d3771d5711a550f2
go run . api --kiln --secret-key 0x607a11b45a7219cc61a3d9c5fd08c7eebd602a6a19a977f8d3771d5711a550f2 --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Query status
curl localhost:9062/eth/v1/builder/status

# Send test validator registrations
curl -X POST localhost:9062/eth/v1/builder/validators -d @testdata/valreg2.json

# Delete previous registrations
redis-cli DEL boost-relay/kiln:validators-registration boost-relay/kiln:validators-registration-timestamp
```

Env vars:

* `ENABLE_ZERO_VALUE_BLOCKS` - set to 1 to send out blocks with 0 value
* `ENABLE_QUERY_PROPOSER_DUTIES_NEXT_EPOCH`
* `DISABLE_SIGNATURE_VERIFICATIONS`