# mev-boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/mev-boost-relay)](https://goreportcard.com/report/github.com/flashbots/mev-boost-relay)
[![Test status](https://github.com/flashbots/mev-boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/mev-boost-relay/actions?query=workflow%3A%22Checks%22)

Flashbots mev-boost relay for proposer/builder separation in Ethereum.

Provides the builder-specs API for Ethereum proof-of-stake validators, an API for block builders to submit blocks, as well as a data API, as running for [Goerli](https://builder-relay-goerli.flashbots.net/) and the other test networks.

The relay consists of several components that are designed to run and scale independently and to be as simple as possible:

1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): update known validators, proposer duties. Soon: save metrics, etc.
2. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): for proposer, block builder, data
3. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): handles the root website requests (information is pulled from Redis and database)

This software is currently in **alpha state**, and there'll be significant changes in the following weeks. In particular major database schema changes, decoupling of block submissions from the proposer API and proper expiry of Redis entries.

See also:

* [mev-boost](https://github.com/flashbots/mev-boost/)
* [Relay API Spec](https://flashbots.notion.site/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5)
* [builder-relay-goerli.flashbots.net](https://builder-relay-goerli.flashbots.net/)

---

# Table of contents

- [Background](#background)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

# Background

MEV is a centralizing force on Ethereum. Unattended, the competition for MEV opportunities leads to consensus security instability and permissioned communication infrastructure between traders and block producers. This erodes neutrality, transparency, decentralization, and permissionlessness.

Flashbots is a research and development organization working on mitigating the negative externalities of MEV. Flashbots started as a builder specializing in MEV extraction in proof-of-work Ethereum to democratize access to MEV and make the most profitable blocks available to all miners. >90% of miners are outsourcing some of their block construction to Flashbots today.

The mev-boost relay is a trusted mediator between block producers and block builders. It enables all Ethereum proof-of-stake validators to offer their blockspace to not just Flashbots but other builders as well. This opens up the market to more builders and creates competition between them, leading to more revenue and choice for validators, and better censorship-resistance for Ethereum.

In the future, [proposer/builder separation](https://ethresear.ch/t/two-slot-proposer-builder-separation/10980) will be enshrined in the Ethereum protocol itself to further harden its trust model.

Read more in [Why run mev-boost?](https://writings.flashbots.net/writings/why-run-mevboost/) and in the [Frequently Asked Questions](https://github.com/flashbots/mev-boost/wiki/Frequently-Asked-Questions).

# Usage

```bash
# Start PostgreSQL & Redis in Docker
docker-compose up

# Or start services individually:
docker run -p 5432:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres postgres
docker run -p 6379:6379 redis
```

Note: this also run a Adminer (a web frontend for Postgres) on http://localhost:8093/?username=postgres (db: `postgres`, username: `postgres`, password: `postgres`)

The services need access to a beacon node for event subscriptions. You can also specify multiple beacon nodes by providing a comma separated list of beacon node URIs. The beacon API by default is using `localhost:3500` (the Prysm default beacon-API port). You can proxy the port from a server like this:

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

Env vars:

* `DB_TABLE_PREFIX` - prefix to use for db tables (default uses `dev`)
* `ENABLE_ZERO_VALUE_BLOCKS` - allow blocks with 0 value
* `SYNC_VALIDATOR_REGISTRATIONS` - handle validator registrations synchronously instead of in a background worker pool
* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests
* `ALLOW_BLOCK_VERIFICATION_FAIL` - accept block even if block simulation & verification fails
* `DISABLE_BID_MEMORY_CACHE` - force bids to go through redis/db

# Maintainers

- [@metachris](https://github.com/metachris)

# Contributing

[Flashbots](https://flashbots.net) is a research and development collective working on mitigating the negative externalities of decentralized economies. We contribute with the larger free software community to illuminate the dark forest.

You are welcome here <3.

- If you have a question, feedback or a bug report for this project, please [open a new Issue](https://github.com/flashbots/mev-boost/issues).
- If you would like to contribute with code, check the [CONTRIBUTING file](CONTRIBUTING.md) for further info about the development environment.
- We just ask you to be nice. Read our [code of conduct](CODE_OF_CONDUCT.md).

# Security

If you find a security vulnerability on this project or any other initiative related to Flashbots, please let us know sending an email to security@flashbots.net.

# License

The code in this project is free software under the [AGPL License version 3 or later](LICENSE).

---

Made with ☀️ by the ⚡🤖 collective.
