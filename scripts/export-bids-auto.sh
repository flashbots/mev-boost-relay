#!/bin/bash
#
# This script automatically determines the latest exported slot and the latest slot on chain, and
# exports all available buckets in between.
#
set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

# number of bids to export per bucket
BUCKET_SIZE=1500

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
echo "SCRIPT_DIR: $SCRIPT_DIR"

# Get the latest previously exported slot from S3
latestslot_exported=$( curl -s https://flashbots-boost-relay-public.s3.us-east-2.amazonaws.com/ | tr '\<' '\n' | sed -n -e 's/.*-to-//p' | sort | tail -n 1 | sed 's/[.].*//' )
echo "latest_slot_exported: $latestslot_exported"

# Get the latest slot on chain
latestslot=$( curl -s https://beaconcha.in/latestState | jq '.lastProposedSlot' )
last_slot_to_export=$((latestslot - (latestslot % BUCKET_SIZE)))
echo "latest slot: $latestslot"
echo "last_slot_to_export:  $last_slot_to_export"

# Invoke the export script now
slot_start=$((latestslot_exported + 1))
slot_end=$last_slot_to_export
cmd="$SCRIPT_DIR/export-bids.sh $slot_start $slot_end"
echo $cmd
$cmd
