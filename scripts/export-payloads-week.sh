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

year_last=$(date -d"last week" +%Y)
year_last=${YEAR:-$year_last}
week_last=$(date -d"last week" +%U)
week_last=${WEEK:-$week_last}

cmd="from datetime import date; d=date.fromisocalendar($year_last, int('$week_last'), 1); print('%s-%s-%02d' % (d.year, d.month, d.day));"
monday_last_week=$(python3 -c "$cmd")
cmd="from datetime import date, timedelta; d=date.fromisocalendar($year_last, int('$week_last'), 1); d=d+timedelta(weeks=1); print('%s-%s-%02d' % (d.year, d.month, d.day));"
monday_this_week=$(python3 -c "$cmd")
echo "$year_last $week_last = $monday_last_week -> $monday_this_week"
# exit 0

fn1="${year_last}_w${week_last}.csv"
fn2="${year_last}_w${week_last}.json"
echo $fn1
echo $fn2
DB_DONT_APPLY_SCHEMA=1 DB_TABLE_PREFIX=mainnet go run . tool data-api-export-payloads --db $DB --date-start $monday_last_week --date-end $monday_this_week --out $fn1 --out $fn2

if [[ -z "$DONTASK" ]]; then
    echo "press enter to upload to S3..."
    read -r
fi

aws --profile l1 s3 cp $fn1 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
aws --profile l1 s3 cp $fn2 s3://flashbots-boost-relay-public/data/1_payloads-delivered/weekly/
