#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [ -z $DB ]; then
        echo "missing postgres dns in DB env var"
        exit 1
fi

date_start_default=$(date -d"last month" +%Y-%m-01)
date_start=${DATE:-$date_start_default}
date_end=$(date -d "$date_start+1 month" +%Y-%m-%d)
echo "$date_start -> $date_end"

fn_base=$(date -d "$date_start" +%Y-%m)
fn1="${fn_base}.csv"
fn2="${fn_base}.json"
echo $fn1
echo $fn2
DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-payloads --db $DB --date-start $date_start --date-end $date_end --out $fn1 --out $fn2

if [[ -z "$DONTASK" ]]; then
    echo "press enter to upload to S3..."
    read -r
fi

aws --profile l1 s3 cp $fn1 s3://flashbots-boost-relay-public/data/1_payloads-delivered/monthly/
aws --profile l1 s3 cp $fn2 s3://flashbots-boost-relay-public/data/1_payloads-delivered/monthly/
