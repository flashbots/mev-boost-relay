# MEV-Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/mev-boost-relay)](https://goreportcard.com/report/github.com/flashbots/mev-boost-relay)
[![Test status](https://github.com/flashbots/mev-boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/mev-boost-relay/actions?query=workflow%3A%22Checks%22)

MEV-Boost Relay for Ethereum proposer/builder separation (PBS).

Currently live at:

* https://boost-relay.flashbots.net (also on [Goerli](https://boost-relay-sepolia.flashbots.net) and [Sepolia](https://boost-relay-goerli.flashbots.net))
* https://relay.ultrasound.money
* https://agnostic-relay.net
* https://relay.edennetwork.io/info
* https://relayooor.wtf
* https://mainnet-relay.securerpc.com
* https://mainnet.aestus.live

The relay consists of several components that are designed to run and scale independently and to be as simple as possible:

1. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): for proposer, block builder, data.
1. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): handles the root website requests (information is pulled from Redis and database).
1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): update known validators, proposer duties.

Dependencies:

1. Redis
1. PostgreSQL
1. one or more [beacon nodes](#running-beacon-node--s-)
1. block submission validation nodes
1. [optional] Memcached

A security assessment for the relay was conducted on 2022-08-22 by [lotusbumi](https://github.com/lotusbumi). Additional information can be found in the [Security](#security) section of this repository.

**See also:**

* [Docker images](https://hub.docker.com/r/flashbots/mev-boost-relay)
* [mev-boost](https://github.com/flashbots/mev-boost)
* [Relay API specs](https://flashbots.github.io/relay-specs)
* [Guider for running mev-boost-relay at scale](https://flashbots.notion.site/Running-mev-boost-relay-at-scale-draft-4040ccd5186c425d9a860cbb29bbfe09)

---

# Table of contents

- [Background](#background)
- [Usage](#usage)
- [Technical notes](#technical-notes)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

# Background

MEV is a centralizing force on Ethereum. Unattended, the competition for MEV opportunities leads to consensus security instability and permissioned communication infrastructure between traders and block producers. This erodes neutrality, transparency, decentralization, and permissionlessness.

Flashbots is a research and development organization working on mitigating the negative externalities of MEV. Flashbots started as a builder specializing in MEV extraction in proof-of-work Ethereum to democratize access to MEV and make the most profitable blocks available to all miners. >90% of miners are outsourcing some of their block construction to Flashbots today.

The mev-boost relay is a trusted mediator between block producers and block builders. It enables all Ethereum proof-of-stake validators to offer their blockspace to not just Flashbots but other builders as well. This opens up the market to more builders and creates competition between them, leading to more revenue and choice for validators, and better censorship-resistance for Ethereum.

In the future, [proposer/builder separation](https://ethresear.ch/t/two-slot-proposer-builder-separation/10980) will be enshrined in the Ethereum protocol itself to further harden its trust model.

Read more in [Why run mev-boost?](https://writings.flashbots.net/writings/why-run-mevboost/) and in the [Frequently Asked Questions](https://github.com/flashbots/mev-boost/wiki/Frequently-Asked-Questions).

---

# Usage

## Running Beacon Node(s)

- The services need access to a beacon node for event subscriptions. 
- You can specify multiple beacon nodes by providing a comma separated list of beacon node URIs.
  - The beacon API by default is using `localhost:3500` (the Prysm default beacon-API port).

### [Option 1] Proxying [Prysm Beacon Node](https://docs.prylabs.network/docs/how-prysm-works/beacon-node)
You can proxy the beacon-API port (eg. 3500 for Prysm) from a server like this:

```bash
ssh -L 3500:localhost:3500 your_server
```

### [Option 2] Running Lighthouse Beacon Node
```bash
docker run --name bn --network=host -v ~/.lighthouse:/lighthouse sigp/lighthouse lighthouse bn --network goerli --execution-endpoint http://localhost:8551 --http --datadir /lighthouse --execution-jwt /lighthouse/jwt.hex
```

### Running Erigon Execution Client
- Ethereum beacon nodes require connection to an execution client to validate block transactions
- Connection between the beacon and execution engine should use a matching JSON Web Token (JWT)
  - For additional details, see: [link](https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md)
```bash
docker run --name erigon -v ~/.erigon:/erigon -p 30303:30303 -p 8545:8545 -p 8551:8551 thorax/erigon:v2.40.1  --datadir /erigon --chain=mainnet --port=30303 --http.port=8545 --http --http.api=eth,debug,net,trace,web3,erigon --prune hrtc --authrpc.port=8551
```

## Running Postgres, Redis and Memcached
```bash
# Start PostgreSQL & Redis individually:
docker run -d -p 5432:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres postgres
docker run -d -p 6379:6379 redis

# [optional] Start Memcached
docker run -d -p 11211:11211 memcached

# Or with docker-compose:
docker-compose up
```

Note: docker-compose also runs an Adminer (a web frontend for Postgres) on http://localhost:8093/?username=postgres (db: `postgres`, username: `postgres`, password: `postgres`)



Now start the services:

```bash
# The housekeeper sets up the validators, and does various housekeeping
go run . housekeeper --network sepolia --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run APIs for sepolia (using a dummy BLS secret key)
go run . api --network sepolia --secret-key 0x607a11b45a7219cc61a3d9c5fd08c7eebd602a6a19a977f8d3771d5711a550f2 --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run Website for sepolia
go run . website --network sepolia --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Query status
curl localhost:9062/eth/v1/builder/status

# Send test validator registrations
curl -X POST localhost:9062/eth/v1/builder/validators -d @testdata/valreg2.json

# Delete previous registrations
redis-cli DEL boost-relay/sepolia:validators-registration boost-relay/sepolia:validators-registration-timestamp
```


### Environment variables

* `ACTIVE_VALIDATOR_HOURS` - number of hours to track active proposers in redis (default: 3)
* `API_TIMEOUT_READ_MS` - http read timeout in milliseconds (default: 1500)
* `API_TIMEOUT_READHEADER_MS` - http read header timeout in milliseconds (default: 600)
* `API_TIMEOUT_WRITE_MS` - http write timeout in milliseconds (default: 10000)
* `API_TIMEOUT_IDLE_MS` - http idle timeout in milliseconds (default: 3000)
* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests (0 for no maximum)
* `BLOCKSIM_TIMEOUT_MS` - builder block submission validation request timeout (default: 3000)
* `DB_DONT_APPLY_SCHEMA` - disable applying DB schema on startup (useful for connecting data API to read-only replica)
* `DB_TABLE_PREFIX` - prefix to use for db tables (default uses `dev`)
* `DISABLE_BID_MEMORY_CACHE` - disable bids to go through in-memory cache. forces to go through redis/db
* `DISABLE_BLOCK_PUBLISHING` - disable publishing blocks to the beacon node at the end of getPayload
* `DISABLE_LOWPRIO_BUILDERS` - reject block submissions by low-prio builders
* `FORCE_GET_HEADER_204` - force 204 as getHeader response
* `GETPAYLOAD_RETRY_TIMEOUT_MS` - getPayload retry getting a payload if first try failed (default: 100)
* `MEMCACHED_ENDPOINTS` - optional comma separated list of memcached endpoints, typically used as secondary storage alongside Redis
* `NUM_ACTIVE_VALIDATOR_PROCESSORS` - proposer API - number of goroutines to listen to the active validators channel
* `NUM_VALIDATOR_REG_PROCESSORS` - proposer API - number of goroutines to listen to the validator registration channel

#### Development Environment Variables
* `RUN_DB_TESTS` - when set to "1" enables integration tests with Postgres using endpoint specified by environment variable `TEST_DB_DSN`
* `RUN_INTEGRATION_TESTS` - when set to "1" enables integration tests, currently used for testing Memcached using comma separated list of endpoints specified by `MEMCACHED_ENDPOINTS`
* `TEST_DB_DSN` - specifies connection string using Data Source Name (DSN) for Postgres (default: postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable)

### Updating the website

* Edit the HTML in `services/website/website.html`
* Edit template values in `testdata/website-htmldata.json`
* Generate a static version of the website with `go run scripts/website-staticgen/main.go`

This builds a local copy of the template and saves it in `website-index.html`

The website is using:
* [PureCSS](https://purecss.io/)
* [HeroIcons](https://heroicons.com/)
* [Font Awesome](https://fontawesome.com/docs) [icons](https://fontawesome.com/icons)

---

# Technical Notes

See [ARCHITECTURE.md](ARCHITECTURE.md) for more technical details!

---

# Maintainers

- [@metachris](https://twitter.com/metachris)
- [@Ruteri](https://twitter.com/mmrosum)
- [@avalonche](https://github.com/avalonche)

# Contributing

[Flashbots](https://flashbots.net) is a research and development collective working on mitigating the negative externalities of decentralized economies. We contribute with the larger free software community to illuminate the dark forest.

You are welcome here <3.

- If you have a question, feedback or a bug report for this project, please [open a new Issue](https://github.com/flashbots/mev-boost/issues).
- If you would like to contribute with code, check the [CONTRIBUTING file](CONTRIBUTING.md) for further info about the development environment.
- We just ask you to be nice. Read our [code of conduct](CODE_OF_CONDUCT.md).

# Security

If you find a security vulnerability on this project or any other initiative related to Flashbots, please let us know sending an email to security@flashbots.net.

## Audits

- [20220822](docs/audit-20220822.md), by [lotusbumi](https://github.com/lotusbumi).

# License

The code in this project is free software under the [AGPL License version 3 or later](LICENSE).

---

Made with ☀️ by the ⚡🤖 collective.
