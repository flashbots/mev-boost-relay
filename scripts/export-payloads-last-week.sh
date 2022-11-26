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

monday_start=$(date -d"last Sunday -6 days" +%Y-%m-%d)
monday_end=$(date -d"last Sunday +1 days" +%Y-%m-%d)
fn1=$(date -d"last week" +%Y_w%U.csv)
fn2=$(date -d"last week" +%Y_w%U.json)
echo "exporting $monday_start to $monday_end -> $fn1 / $fn2"
echo $fn1
echo $fn2
DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-payloads --db $DB --date-start $monday_start --date-end $monday_end --out $fn1 --out $fn2

echo "press enter to upload to S3..."
read -r
aws --profile l1 s3 cp $fn1 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
aws --profile l1 s3 cp $fn2 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
