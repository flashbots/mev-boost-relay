# Boost Relay

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/boost-relay)](https://goreportcard.com/report/github.com/flashbots/boost-relay)
[![Test status](https://github.com/flashbots/boost-relay/workflows/Checks/badge.svg)](https://github.com/flashbots/boost-relay/actions?query=workflow%3A%22Checks%22)

Example [mev-boost](https://github.com/flashbots/mev-boost/) relay for Eth2 after the merge.

* Exposes a Builder REST API for mev-boost / CL clients / proposers
* Exposes an API for builders to send blocks
* Exposes a JSON-RPC API to receive [engine_forkchoiceUpdatedV1](https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#engine_forkchoiceupdatedv1) (FCU) calls from the BN

## System Architecture

The main question is: how does the builder know which slot and proposer to prepare the block for?

* The beacon-node triggers start of working, using forkchoiceUpdated (FCU)
* FCU doesn't have the slot or the proposer
* We wanted to make minimal changes to the BN to make things work

This relay works as follows:

* We run a beacon node with patched FCU, which calls the relay on every slot (https://github.com/flashbots/lighthouse/pull/1)
* Relay asks BN for current proposer+slot
* Relay calls builder with all infos to trigger block construction

![boost-relay architecture](https://raw.githubusercontent.com/flashbots/boost-relay/main/docs/orverview.png)

([source](https://excalidraw.com/#json=l2Dy6WbGP59PvfBV4v2Fe,7hHy4xO_wtYpyv04vxfH6g))

```mermaid
sequenceDiagram
    Title: Block Proposal
    participant Beacon Node
    participant Boost Relay
    participant Builder

    Note over Boost Relay: regularly update proposers of an epoch
    Boost Relay->>Beacon Node: /eth/v1/validator/duties/proposer/{epoch}

    Note over Beacon Node: new slot
    Beacon Node->>Boost Relay: FCU

    Note over Boost Relay: fetch current slot (and proposer)
    Boost Relay->>Beacon Node: /eth/v1/beacon/headers

    Note over Boost Relay: tell builder to start work
    Boost Relay->>Builder: startWork

    Note over Builder: Send new blocks as they are computed
    Builder->>Boost Relay: newBlock
```
