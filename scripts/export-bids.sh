#!/bin/bash
set -o errexit
# set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

# number of bids to export per bucket
BUCKET_SIZE="${BUCKET_SIZE:-4000}"

if [ -z $DB ]; then
        echo "missing postgres dns in DB env var"
        exit 1
fi

if [ -z $1 ]; then
        echo "missing slot-from arg1"
        exit 1
fi

if [ -z $2 ]; then
        echo "missing slot-to arg2"
        exit 1
fi

function export() {
        start=$1
        end=$2
        echo "exporting bids from slots $start -> $end"
        fn1="builder-submissions_slot-${start}-to-${end}.csv"
        fn2="builder-submissions_slot-${start}-to-${end}.json"
        DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-bids --db $DB --slot-from $start --slot-to $end --out $fn1 --out $fn2

        echo "compressing $fn1 ..."
        gzip $fn1
        echo "compressing $fn2 ..."
        gzip $fn2

        echo "uploading to s3..."
        aws --profile l1 s3 cp ./$fn1.gz s3://flashbots-boost-relay-public/data/2_builder-submissions/
        aws --profile l1 s3 cp ./$fn2.gz s3://flashbots-boost-relay-public/data/2_builder-submissions/

       if [ "$DELETE" == "1" ]; then
               rm -f $fn1* $fn2*
       fi
}

start=$1
slot_end=$2

while [[ $start -le $slot_end ]]; do
        end=$((start+BUCKET_SIZE-1))
        if [[ $end -gt $slot_end ]]; then
                end=$slot_end
        fi
        # echo "exporting bids from slots $start -> $end"
        export $start $end
        start=$((end+1))
done
