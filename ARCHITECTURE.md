Notes about the architecture and usage of the relay.

See also:

* https://github.com/flashbots/mev-boost-relay
* https://github.com/flashbots/mev-boost-relay/issues

This document covers more details about running a relay at scale: https://flashbots.notion.site/Draft-Running-a-relay-4040ccd5186c425d9a860cbb29bbfe09

## Overview

The relay consists of three main components:

1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): update known validators and proposer duties, and syncs DB->Redis on startup. Needs to run as single instance, will be replaced by cronjob in the future.
1. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): handles the root website requests (information is pulled from Redis and database).
1. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): for proposer, block builder, data.

The API can run as a single instance, but for production can (and should) be deployed and scaled independently! These are the recommended deployments:

1. Proposer API (registerValidator, getHeader, getPayload)
1. Builder API (getValidatorDuties, submitNewBlock)
1. Data API (read-only access to DB read replica)
1. Internal API (setting builder status)

---

## Logging

* Logs with level `error` are always system errors and something to investigate (never use the error level for bad request payloads or other user errors).
* Put differently: if you want to make an error show up in the logs and dashboards, then use the `error` level!

---

## Utilities

* https://github.com/buger/jsonparser for really fast JSON request body processing

---

## System startup sequence

* First, Redis and Postgres have to be ready, as well as the beacon node(s)
* The housekeeper syncs important data from the beacon node and database to Redis
* The API needs access to the data in Redis to operate (i.e. all bids are going through Redis)

### Housekeeper

The housekeeper updates Redis with important information:

1. Active and pending validators (source: beacon node)
1. Proposer duties (source: beacon node (duties) + database (validator registrations))
1. Validator registrations (source: database)
1. Builder status (source: database)

Afterwards, there's important ongoing, regular housekeeper tasks:

1. Update known validators and proposer duties in Redis
2. Update active validators in database (source: Redis) (TODO)

---

## Tradeoffs

- Validator registrations in are only saved to the database if `feeRecipient` or `gasLimit` changed. If a registration has a newer timestamp but same `feeRecipient` and `gasLimit` it is not saved, to avoid filling up the database with unnecessary data.
  (some CL clients create a new validator registration every epoch, not just if preferences change, as was the original idea).

---

## Infrastructure

A full infrastructure might include these components:

1. Load balancer + Firewall
1. 2x proposer API (4 CPU, 1GB RAM)
1. 2x builder API (2-4 CPU, 1GB RAM)
1. 2x data API (1 CPU, 1GB RAM)
1. 2x website (1 CPU, 2GB RAM)
1. 1x housekeeper (2 CPU, 1GB RAM)
1. Redis (4GB)
1. Postgres DB (100GB+)
1. A bunch of beacon-nodes (3 for redundancy?)
1. Block validation EL nodes

For more discussion about running a relay see also https://collective.flashbots.net/t/ideas-for-incentivizing-relays/586

---

## Further notes

* Use [architecture decision records (ADRs)](https://github.com/joelparkerhenderson/architecture-decision-record) based on [this template](https://github.com/joelparkerhenderson/architecture-decision-record/blob/main/templates/decision-record-template-by-michael-nygard/index.md)