# MEV-Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/mev-boost-relay)](https://goreportcard.com/report/github.com/flashbots/mev-boost-relay)
[![Test status](https://github.com/flashbots/mev-boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/mev-boost-relay/actions?query=workflow%3A%22Checks%22)
[![Docker hub](https://badgen.net/docker/size/flashbots/mev-boost-relay?icon=docker&label=image)](https://hub.docker.com/r/flashbots/mev-boost-relay/tags)

MEV-Boost Relay for Ethereum proposer/builder separation (PBS).

Currently live at:

* [boost-relay.flashbots.net](https://boost-relay.flashbots.net) (also on [Goerli](https://boost-relay-goerli.flashbots.net),  [Sepolia](https://boost-relay-sepolia.flashbots.net) and [Holesky](https://boost-relay-holesky.flashbots.net))
* [relay.ultrasound.money](https://relay.ultrasound.money), [agnostic-relay.net](https://agnostic-relay.net), bloXroute relays ([light fork](https://github.com/bloXroute-Labs/mev-relay))
* [mainnet.aestus.live](https://mainnet.aestus.live), [relay.edennetwork.io/info](https://relay.edennetwork.io/info), [mainnet-relay.securerpc.com](https://mainnet-relay.securerpc.com)

Alternatives (not audited or endorsed): [blocknative/dreamboat](https://github.com/blocknative/dreamboat), [manifold/mev-freelay](https://github.com/manifoldfinance/mev-freelay)

### See also

* [Docker images](https://hub.docker.com/r/flashbots/mev-boost-relay)
* [mev-boost](https://github.com/flashbots/mev-boost)
* [Relay API specs](https://flashbots.github.io/relay-specs)
* [Guide for running mev-boost-relay at scale](https://flashbots.notion.site/Running-mev-boost-relay-at-scale-draft-4040ccd5186c425d9a860cbb29bbfe09)
* [Running relay and builders in custom devnets](https://gist.github.com/metachris/66df812f2920e6b0047afb9fdaf7df91#using-unnamed-devnets)
* [More docs](/docs/docs/)

### Components

The relay consists of three main components, which are designed to run and scale independently, and to be as simple as possible:

1. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): Services that provide APIs for (a) proposers, (b) block builders, (c) data.
1. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): Serving the [website requests](https://boost-relay.flashbots.net/) (information is pulled from Redis and database).
1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): Updates known validators, proposer duties, and more in the background. Only a single instance of this should run.

### Dependencies

1. Redis
1. PostgreSQL
1. one or more beacon nodes
1. block submission validation nodes
1. [optional] Memcached

### Beacon nodes / CL clients

- The relay services need access to one or more beacon node for event subscriptions (in particular the `head` and `payload_attributes` topics).
- You can specify multiple beacon nodes by providing a comma separated list of beacon node URIs.
- The beacon nodes need to support the [`payload_attributes` SSE event](https://github.com/ethereum/beacon-APIs/pull/305).
- Support the [v2 CL publish block endpoint](https://github.com/ethereum/beacon-APIs/pull/317) in the current main branch, since August 2. This is still
  experimental and may or may not fully work. It requires at least one of these CL clients
  - **Lighthouse+** [v4.3.0](https://github.com/sigp/lighthouse/releases) or later. Here's a [quick guide](https://gist.github.com/metachris/bcae9ae42e2fc834804241f991351c4e) for setting up Lighthouse.
  - **Prysm** [v4.0.6](https://github.com/prysmaticlabs/prysm/releases) or later.
- The latest release (v0.26) still uses the old V1 broadcast endpoint using CL clients with custom validate-before-broadcast patches (see [README of the release for more details](https://github.com/flashbots/mev-boost-relay/tree/v0.26#beacon-nodes--cl-clients))

**Relays are strongly advised to run multiple beacon nodes!**
* The reason is that on getPayload, the block has to be validated and broadcast by a local beacon node before it is returned to the proposer.
* If the local beacon nodes don't accept it (i.e. because it's down), the block won't be returned to the proposer, which leads to the proposer missing the slot.
* The relay makes the validate+broadcast request to all beacon nodes concurrently, and returns as soon as the first request is successful.

### Security

A security assessment for the relay was conducted on 2022-08-22 by [lotusbumi](https://github.com/lotusbumi). Additional information can be found in the [Security](#security) section of this repository.

If you find a security vulnerability on this project or any other initiative related to Flashbots, please let us know sending an email to security@flashbots.net.

---

# Background

MEV is a centralizing force on Ethereum. Unattended, the competition for MEV opportunities leads to consensus security instability and permissioned communication infrastructure between traders and block producers. This erodes neutrality, transparency, decentralization, and permissionlessness.

Flashbots is a research and development organization working on mitigating the negative externalities of MEV. Flashbots started as a builder specializing in MEV extraction in proof-of-work Ethereum to democratize access to MEV and make the most profitable blocks available to all miners. >90% of miners are outsourcing some of their block construction to Flashbots today.

The mev-boost relay is a trusted mediator between block producers and block builders. It enables all Ethereum proof-of-stake validators to offer their blockspace to not just Flashbots but other builders as well. This opens up the market to more builders and creates competition between them, leading to more revenue and choice for validators, and better censorship-resistance for Ethereum.

In the future, [proposer/builder separation](https://ethresear.ch/t/two-slot-proposer-builder-separation/10980) will be enshrined in the Ethereum protocol itself to further harden its trust model.

Read more in [Why run mev-boost?](https://writings.flashbots.net/writings/why-run-mevboost/) and in the [Frequently Asked Questions](https://github.com/flashbots/mev-boost/wiki/Frequently-Asked-Questions).

---

# Usage

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
curl -X POST -H'Content-Encoding: gzip' localhost:9062/eth/v1/builder/validators --data-binary @testdata/valreg2.json.gz

# Delete previous registrations
redis-cli DEL boost-relay/sepolia:validators-registration boost-relay/sepolia:validators-registration-timestamp
```


## Environment variables

#### General

* `ACTIVE_VALIDATOR_HOURS` - number of hours to track active proposers in redis (default: `3`)
* `API_MAX_HEADER_BYTES` - http maximum header bytes (default: `60_000`)
* `API_TIMEOUT_READ_MS` - http read timeout in milliseconds (default: `1_500`)
* `API_TIMEOUT_READHEADER_MS` - http read header timeout in milliseconds (default: `600`)
* `API_TIMEOUT_WRITE_MS` - http write timeout in milliseconds (default: `10_000`)
* `API_TIMEOUT_IDLE_MS` - http idle timeout in milliseconds (default: `3_000`)
* `API_SHUTDOWN_WAIT_SEC` - how long to wait on shutdown before stopping server, to allow draining of requests (default: `30`)
* `API_SHUTDOWN_STOP_SENDING_BIDS` - whether API should stop sending bids during shutdown (nly useful in single-instance/testnet setups, default: `false`)
* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests (0 for no maximum, default: `4`)
* `BLOCKSIM_TIMEOUT_MS` - builder block submission validation request timeout (default: `3000`)
* `BROADCAST_MODE` - which broadcast mode to use for block publishing (default: `consensus_and_equivocation`)
* `DB_DONT_APPLY_SCHEMA` - disable applying DB schema on startup (useful for connecting data API to read-only replica)
* `DB_TABLE_PREFIX` - prefix to use for db tables (default uses `dev`)
* `GETPAYLOAD_RETRY_TIMEOUT_MS` - getPayload retry getting a payload if first try failed (default: `100`)
* `MEMCACHED_URIS` - optional comma separated list of memcached endpoints, typically used as secondary storage alongside Redis
* `MEMCACHED_EXPIRY_SECONDS` - item expiry timeout when using memcache (default: `45`)
* `MEMCACHED_CLIENT_TIMEOUT_MS` - client timeout in milliseconds (default: `250`)
* `MEMCACHED_MAX_IDLE_CONNS` - client max idle conns (default: `10`)
* `NUM_ACTIVE_VALIDATOR_PROCESSORS` - proposer API - number of goroutines to listen to the active validators channel
* `NUM_VALIDATOR_REG_PROCESSORS` - proposer API - number of goroutines to listen to the validator registration channel
* `NO_HEADER_USERAGENTS` - proposer API - comma separated list of user agents for which no bids should be returned
* `ENABLE_BUILDER_CANCELLATIONS` - whether to enable block builder cancellations
* `REDIS_URI` - main redis URI (default: `localhost:6379`)
* `REDIS_READONLY_URI` - optional, a secondary redis instance for heavy read operations

#### Feature Flags

* `DISABLE_PAYLOAD_DATABASE_STORAGE` - builder API - disable storing execution payloads in the database (i.e. when using memcached as data availability redundancy)
* `DISABLE_LOWPRIO_BUILDERS` - reject block submissions by low-prio builders
* `FORCE_GET_HEADER_204` - force 204 as getHeader response
* `ENABLE_IGNORABLE_VALIDATION_ERRORS` - enable ignorable validation errors
* `USE_V1_PUBLISH_BLOCK_ENDPOINT` - uses the v1 publish block endpoint on the beacon node
* `USE_SSZ_ENCODING_PUBLISH_BLOCK` - uses the SSZ encoding for the publish block endpoint

#### Development Environment Variables

* `RUN_DB_TESTS` - when set to "1" enables integration tests with Postgres using endpoint specified by environment variable `TEST_DB_DSN`
* `RUN_INTEGRATION_TESTS` - when set to "1" enables integration tests, currently used for testing Memcached using comma separated list of endpoints specified by `MEMCACHED_URIS`
* `TEST_DB_DSN` - specifies connection string using Data Source Name (DSN) for Postgres (default: postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable)

#### Redis Tuning

* `REDIS_CONNECTION_POOL_SIZE`, `REDIS_MIN_IDLE_CONNECTIONS`, `REDIS_READ_TIMEOUT_SEC`, `REDIS_POOL_TIMEOUT_SEC`, `REDIS_WRITE_TIMEOUT_SEC` (see also [the code here](https://github.com/flashbots/mev-boost-relay/blob/e39cd38010de26bf9a51d1a3e77fc235ea87b12f/datastore/redis.go#L35-L41))

#### Website

* `LINK_BEACONCHAIN` - url for beaconcha.in (default: `https://beaconcha.in`)
* `LINK_DATA_API` - origin url for data api (https://domain:port)
* `LINK_ETHERSCAN` - url for etherscan (default: `https://etherscan.io`)
* `LISTEN_ADDR` - listen address for webserver (default: `localhost:9060`)
* `RELAY_URL` - full url for the relay (https://pubkey@host)
* `SHOW_CONFIG_DETAILS` - when set to "1", logs configuration details

## Updating the website

* Edit the HTML in `services/website/website.html`
* Edit template values in `testdata/website-htmldata.json`
* Generate a static version of the website with `go run scripts/website-staticgen/main.go`

This builds a local copy of the template and saves it in `website-index.html`

The website is using:
* [PureCSS](https://purecss.io/)
* [HeroIcons](https://heroicons.com/)

---

# Technical Notes

See [ARCHITECTURE.md](ARCHITECTURE.md) and [Running MEV-Boost-Relay at scale](https://flashbots.notion.site/Draft-Running-a-relay-4040ccd5186c425d9a860cbb29bbfe09) for more technical details!

## Storing execution payloads and redundant data availability

By default, the execution payloads for all block submission are stored in Redis and also in the Postgres database,
to provide redundant data availability for getPayload responses. But the database table is not pruned automatically,
because it takes a lot of resources to rebuild the indexes (and a better option is using `TRUNCATE`).

Storing all the payloads in the database can lead to terabytes of data in this particular table. Now it's also possible
to use memcached as a second data availability layer. Using memcached is optional and disabled by default.

To enable memcached, you just need to supply the memcached URIs either via environment variable (i.e.
`MEMCACHED_URIS=localhost:11211`) or through command line flag (`--memcached-uris`).

You can disable storing the execution payloads in the database with this environment variable:
`DISABLE_PAYLOAD_DATABASE_STORAGE=1`.

## Builder submission validation nodes

You can use the [builder project](https://github.com/flashbots/builder) to validate block builder submissions: https://github.com/flashbots/builder

Here's an example systemd config:

<details>
<summary><code>/etc/systemd/system/geth.service</code></summary>

```ini
[Unit]
Description=mev-boost
Wants=network-online.target
After=network-online.target

[Service]
User=ubuntu
Group=ubuntu
Environment=HOME=/home/ubuntu
Type=simple
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=90
Restart=on-failure
RestartSec=10s
ExecStart=/home/ubuntu/builder/build/bin/geth \
    --syncmode=snap \
    --datadir /var/lib/goethereum \
    --metrics \
    --metrics.expensive \
    --http \
    --http.api="engine,eth,web3,net,debug,flashbots" \
    --http.corsdomain "*" \
    --http.addr "0.0.0.0" \
    --http.port 8545 \
    --http.vhosts '*' \
    --ws \
    --ws.api="engine,eth,web3,net,debug" \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --ws.api engine,eth,net,web3 \
    --ws.origins '*' \
    --graphql \
    --graphql.corsdomain '*' \
    --graphql.vhosts '*' \
    --authrpc.addr="0.0.0.0" \
    --authrpc.jwtsecret=/var/lib/goethereum/jwtsecret \
    --authrpc.vhosts '*' \
    --cache=8192

[Install]
WantedBy=multi-user.target
```
</details>

Sending blocks to the validation node:

- The built-in [blocksim-ratelimiter](services/api/blocksim_ratelimiter.go) is a simple example queue implementation.
- By default, `BLOCKSIM_MAX_CONCURRENT` is set to 4, which allows 4 concurrent block simulations per API node
- For production use, use the [prio-load-balancer](https://github.com/flashbots/prio-load-balancer) project for a single priority queue,
  and disable the internal concurrency limit (set `BLOCKSIM_MAX_CONCURRENT` to `0`).

## Beacon node setup

### Lighthouse

- Lighthouse with validation and equivocaation check before broadcast: https://github.com/sigp/lighthouse/pull/4168
- with `--always-prepare-payload` and `--prepare-payload-lookahead 12000` flags, and some junk feeRecipeint

Here's a [quick guide](https://gist.github.com/metachris/bcae9ae42e2fc834804241f991351c4e) for setting up Lighthouse.

Here's an example Lighthouse systemd config:

<details>
<summary><code>/etc/systemd/system/lighthouse.service</code></summary>

```ini
[Unit]
Description=Lighthouse
After=network.target
Wants=network.target

[Service]
User=ubuntu
Group=ubuntu
Type=simple
Restart=always
RestartSec=5
TimeoutStopSec=180
ExecStart=/home/ubuntu/.cargo/bin/lighthouse bn \
        --network mainnet \
        --checkpoint-sync-url=https://mainnet-checkpoint-sync.attestant.io \
        --eth1 \
        --http \
        --http-address "0.0.0.0" \
        --http-port 3500 \
        --datadir=/mnt/data/lighthouse \
        --http-allow-sync-stalled \
        --execution-endpoints=http://localhost:8551 \
        --jwt-secrets=/var/lib/goethereum/jwtsecret \
        --disable-deposit-contract-sync \
        --always-prepare-payload \
        --prepare-payload-lookahead 12000

[Install]
WantedBy=default.target
```

</details>


### Prysm

- Prysm with validation and equivocaation check before broadcast: https://github.com/prysmaticlabs/prysm/pull/12335
- use `--grpc-max-msg-size 104857600`, because by default the getAllValidators response is too big and fails

Here's an example Prysm systemd config:

<details>
<summary><code>/etc/systemd/system/prysm.service</code></summary>

```ini
[Unit]
Description=Prysm
After=network.target
Wants=network.target

[Service]
User=ubuntu
Group=ubuntu
Type=simple
Restart=always
RestartSec=5
TimeoutStopSec=180
ExecStart=/home/ubuntu/prysm/bazel-bin/cmd/beacon-chain/beacon-chain_/beacon-chain \
        --accept-terms-of-use \
        --enable-debug-rpc-endpoints \
        --checkpoint-sync-url=https://mainnet-checkpoint-sync.attestant.io \
        --genesis-beacon-api-url=https://mainnet-checkpoint-sync.attestant.io \
        --grpc-gateway-host "0.0.0.0" \
        --datadir=/mnt/data/prysm \
        --p2p-max-peers 100 \
        --execution-endpoint=http://localhost:8551 \
        --jwt-secret=/var/lib/goethereum/jwtsecret \
        --min-sync-peers=1 \
        --grpc-max-msg-size 104857600 \
        --prepare-all-payloads \
        --disable-reorg-late-blocks

[Install]
WantedBy=default.target
```

</details>

## Bid Cancellations

Block builders can opt into cancellations by submitting blocks to `/relay/v1/builder/blocks?cancellations=1`. This may incur a performance penalty (i.e. validation of submissions taking significantly longer). See also https://github.com/flashbots/mev-boost-relay/issues/348

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
