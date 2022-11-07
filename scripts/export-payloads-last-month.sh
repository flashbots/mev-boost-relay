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

date_start=$(date -d"last month" +%Y-%m-01)
date_end=$(date +%Y-%m-01)
echo "$date_start -> $date_end"
fn1=$(date -d"last month" +%Y-%m.csv)
fn2=$(date -d"last month" +%Y-%m.json)
echo $fn1
echo $fn2
DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-payloads --db $DB --date-start $date_start --date-end $date_end --out $fn1 --out $fn2

echo "press enter to upload to S3..."
read -r
aws --profile l1 s3 cp $fn1 s3://flashbots-boost-relay-public/data/1_payloads-delivered/monthly/
aws --profile l1 s3 cp $fn2 s3://flashbots-boost-relay-public/data/1_payloads-delivered/monthly/
