Notes about the architecture and usage of the relay.

## Overview

The relay consists of three components that are designed to run and scale independently:

1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): update known validators, proposer duties.
1. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): handles the root website requests (information is pulled from Redis and database).
1. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): for proposer, block builder, data.

The API can be deployed and scaled independently, in particular for these duties:

1. Proposer API (registerValidator, getHeader, getPayload)
1. Builder API (getValidatorDuties, submitNewBlock)
1. Data API (read-only access to DB read replica)
1. Internal API (setting builder status)

---

## Logging

* Logs with level `error` are always system errors and something to investigate (never use the error level for bad request payloads or other user errors).
* Put differently: if you want to make an error show up in the logs and dashboards, then use the `error` level!


---

## Possible optimisations

Possible registerValidator optimisations:
- GetValidatorRegistrationTimestamp could keep a cache in memory for some time and check memory first before going to Redis
- Do multiple loops and filter down set of registrations, and batch checks for all registrations instead of locking for each individually:
  (1) sanity checks, (2) IsKnownValidator, (3) CheckTimestamp, (4) Batch SetValidatorRegistration

---

## Utilities

* https://github.com/buger/jsonparser for really fast JSON request body processing

