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
BUCKET_SIZE="${BUCKET_SIZE:-4000}"
echo "bucket_size: $BUCKET_SIZE"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# echo "SCRIPT_DIR: $SCRIPT_DIR"

# Get the latest previously exported slot from S3
latestslot_exported=$( curl -s https://flashbots-boost-relay-public.s3.us-east-2.amazonaws.com/ | tr '\<' '\n' | sed -n -e 's/.*-to-//p' | sort | tail -n 1 | sed 's/[.].*//' )
echo "latest_slot_exported: $latestslot_exported"

# Get the latest slot on chain
latestslot=$( curl -s https://beaconcha.in/latestState | jq '.lastProposedSlot' )
echo "latest slot: $latestslot"

# Start at last exported slot +1
slot_start=$((latestslot_exported + 1))

# Now loop over buckets until all slots are exported
while true; do
        slot_end=$((slot_start + BUCKET_SIZE - 1))
        echo "slots to export: $slot_start - $slot_end"

        # End now if latest slot to export is in the future
        if (( slot_end > latestslot )); then
               echo "latest slot to export is in the future. exiting now"
               exit 0
        fi

        # Export now
        cmd="$SCRIPT_DIR/export-bids.sh $slot_start $slot_end"
        echo $cmd
        $cmd
        slot_start=$((slot_start + BUCKET_SIZE))
done