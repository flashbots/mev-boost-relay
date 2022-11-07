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

week_last=$(date -d"last week" +%U)
monday_last_week=$(date -d"last week monday" +%Y-%m-%d)
monday_this_week=$(date -d"this week monday" +%Y-%m-%d)
fn1=$(date -d"last week" +%Y_%U.csv)
fn2=$(date -d"last week" +%Y_%U.json)
echo "week $week_last = $monday_last_week to $monday_this_week"
echo $fn1
echo $fn2
DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-payloads --db $DB --date-start $monday_last_week --date-end $monday_this_week --out $fn1 --out $fn2

echo "press enter to upload to S3..."
read -r
aws --profile l1 s3 cp $fn1 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
aws --profile l1 s3 cp $fn2 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
