# MEV-Boost-Relay Database Migration Guide

2023-06-14, by [@0x416e746f6e](https://github.com/0x416e746f6e), [@metachris](https://twitter.com/metachris)

---

`mev-boost-relay` stores the payloads for all builder submissions in the
Postgres database, in addition to Redis, and the database storage is also used
as data availability fallback in case Redis cannot retrieve the payload.

Payloads are quite big, typically a few hundred kilobytes, with a few hundred
submissions per slot. This can make the database grow rapidly to many terabytes
of storage, which in turn adds significant operating costs for the Postgres
database service.

There are several approaches to deal with the Postgres payload storage, and to
avoid storage growth:

1. Truncating the table `mainnet_execution_payload` regularly (possibly
   archiving the payloads to a secondary, cheaper long-term storage).

2. Not storing the payloads in the database at all, which can be configured
   through the `DISABLE_PAYLOAD_DATABASE_STORAGE` environment variable. In this
   case, it’s strongly advised to enable Memcached as secondary payload storage.

Cloud providers like AWS and Google Cloud don’t allow downscaling database
storage sizes of their managed Postgres services. Therefore, if you want to
reduce the costs by downscaling storage, you’ll need to migrate the data to a
new database.

This guide will help you with that.

---

Approaches we tried:

- [AWS DMS](https://aws.amazon.com/dms/) (which is
  [Qlik Replicate](https://www.qlik.com/us/products/qlik-replicate) under the
  hood, if we are any good in searching the internet for error messages)

- [pgsync](https://github.com/ankane/pgsync)

- [pgcopydb](https://github.com/dimitri/pgcopydb)

None of the above (and other less note-worthy) options worked as expected:

- DMS would seem to work in the beginning, but after a few hours of running it
  would start to yield some very cryptic error messages, the solutions to which
  would recommend tweaking Qlik's configuration parameters (to which we
  obviously did not have access to, as they are hidden behind AWS console).

- `pgsync`/`pgcopydb` were found to be not mature enough (not yet at least) to
  deal with the amount of data updates that their respective
  [CDC](https://www.qlik.com/us/change-data-capture/cdc-change-data-capture)
  solutions would have to cope with while migrating our instance.

Which is why we opted to come up with our own (a bit creative, but work-able)
solution.

## TL;DR

Therefore the idea of the migration was as follows:

1. Spin-up a new PSQL instance (with the desired initial storage size).

2. Copy the schema from old to new instance.

3. Transfer the big tables (there were 3 of them) using batch-by-batch
   `COPY TO`/`COPY FROM` statements. (In the order from bigger to smaller
   tables, as the largest table took several days to transfer).

4. Transfer the rest of data using just `pg_dump`.

5. Transfer what had accumulated in the 3 largest tables between steps 3 and 4.

6. Update sequences on the new DB so that they would begin not from `1` but from
   some wittingly big number (next power of 10 above the current latest `id`).

7. Stop the services that write into the old DB → switch them to the new
   instance → start those services again.

8. Switch the read-only services to the new DB (and restart them too).

9. Back-fill whatever new inserts were accumulated in the old DB between the
   moment data was last pumped and the moment of the switch-over.

The approach we used worked as-expected because:

- All `mev-boost-relay`'s significant tables use PSQL's auto-incrementing
  primary keys (that are in fact
  [PSQL’s sequences](https://www.postgresql.org/docs/current/sql-createsequence.html)
  under the hood).

- All updates to the existing records (e.g. `xxx_blockbuilder.last_submission_slot`)
  are of temporal nature. This means that if we miss to migrate an update to the
  old instance, it's not a big deal as *eventually* there would be the next
  update to the same record in the *new* instance that will "make things
  all-right".

Below we provide a bunch of scripts and queries that our fellow peers might find
handy shall they want to migrate away from a huge PSQL and save some costs.

> **Disclaimer:**
>
> Do not trust this blindly!  an experimental migration on some non-critical
> instance is highly advised (e.g. if you run something in goerli, that would be
> a good candidate).

## License

All scripts/queries in this article come with MIT license.

```text
Copyright (c) 2023 Flashbots

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Queries

`active-sessions.sql`

Helps to track current sessions to old/new instance (to make sure that all
writing services are indeed migrated).

```sql
select
    client_addr,
    string_agg(datname || '(' || pids || ')', ', ') as dbs
from (
    select
        client_addr,
        datname,
        string_agg(pid::varchar, ',') as pids
    from pg_stat_activity
    where
            datname is not null and datname != 'rdsadmin'
        and client_addr != 'xxx.yyy.zzz.nnn' -- Put your jumphost IP here
    group by client_addr, datname
    order by client_addr
) as t
group by client_addr
order by client_addr;
```

`alter-sequence.sql`

Query that generates a few other queries that should be ran on the *target*
instance to update the sequences’ current values.

Note the `power(10, ceil(log(last_value)))` bit. If you find it a bit wasteful,
you can change the logic to something else (e.g. do simple `+ 10000`). Just make
sure to avoid collisions when backfilling the records from old instance.

```sql
select
    'alter sequence ' || sequence_name || ' start ' || new_start || '; select setval(''' || sequence_name || ''', ' || new_start || ', false);' as alter_statement
from (
    select *,
        power(10, ceil(log(last_value))) as new_start
    from (
        select *,
            pg_sequence_last_value(sequence_name) as last_value
        from (
            select table_name, column_name,
                pg_get_serial_sequence(table_name, column_name) as sequence_name
            from information_schema.columns
            where table_schema = 'public'
                and pg_get_serial_sequence(table_name, column_name) is not null
        ) as t
    ) as t
    where last_value is not null
) as t
order by 1;
```

## Scripts

With the three scripts below the whole migration can be expressed like:

```bash
# Migrate the schema

mkdir -p ./schema

PGSRCDB=[SOURCE_DB_ID] ./get-schema.sh > ./schema/boostrelay.sql
PGDSTDB=[TARGET_DB_ID] ./put.sh < ./schema/boostrelay.sql

# Migrate the large tables

mkdir -p ./log

time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_builder_block_submission 10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_builder_block_submission.log
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_payload_delivered        10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_payload_delivered.log
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_validator_registration   10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_validator_registration.log

# Backfill what was added to large tables in the mean time

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_validator_registration > ./.temp/mainnet_validator_registration.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_validator_registration   10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_validator_registration.log

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_payload_delivered > ./.temp/mainnet_payload_delivered.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_payload_delivered        10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_payload_delivered.log

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_builder_block_submission > ./.temp/mainnet_builder_block_submission.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_builder_block_submission 10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_builder_block_submission.log

# Migrate the rest of the tables

time ( PGSRCDB=[SOURCE_DB_ID] ./get-data-with-copy.sh mainnet_builder_demotions    | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_builder_demotions.log
time ( PGSRCDB=[SOURCE_DB_ID] ./get-data-with-copy.sh mainnet_execution_payload    | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_execution_payload.log
time ( PGSRCDB=[SOURCE_DB_ID] ./get-data-with-copy.sh mainnet_migrations           | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_migrations.log
time ( PGSRCDB=[SOURCE_DB_ID] ./get-data-with-copy.sh mainnet_blockbuilder         | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_blockbuilder.log
time ( PGSRCDB=[SOURCE_DB_ID] ./get-data-with-copy.sh mainnet_too_late_get_payload | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_too_late_get_payload.log

### Do the switch here ###

# Backfill what was added to large tables in between the switch

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_validator_registration > ./.temp/mainnet_validator_registration.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_validator_registration   10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_validator_registration.log

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_payload_delivered > ./.temp/mainnet_payload_delivered.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_payload_delivered        10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_payload_delivered.log

PGDSTDB=[TARGET_DB_ID] ./get-start-id.sh mainnet_builder_block_submission > ./.temp/mainnet_builder_block_submission.cur
time ( PGSRCDB=[SOURCE_DB_ID] ./batch-load.sh mainnet_builder_block_submission 10000 | PGDSTDB=[TARGET_DB_ID] ./put.sh ) 2> ./log/mainnet_builder_block_submission.log

```

---

`put.sh`

The workhorse that fills the data into the target DB. Unmentioned `PGPASSWORD`
env var should be set to the password used by both old and new instances.

```bash
#!/bin/bash

if [[ -z "${PGDSTHOST}" ]]; then echo "Missing PGDSTHOST"; exit 1; fi
if [[ -z "${PGDSTDB}" ]]; then echo "Missing PGDSTDB"; exit 1; fi

# shellcheck disable=SC2312
cat - | >&2 psql \
  --host "${PGDSTHOST}"  \
  --dbname "${PGDSTDB}" \
  --username postgres
```

---

`get-schema.sh`

Retrieves just the schema from the source DB. (Note, you might need to first
transfer all the users/roles by hand).

```bash
#!/bin/bash

if [[ -z "${PGSRCHOST}" ]]; then echo "Missing PGSRCHOST"; exit 1; fi
if [[ -z "${PGSRCDB}" ]]; then echo "Missing PGSRCDB"; exit 1; fi

if [[ -z "$1" ]]; then
  pg_dump \
    --host "${PGSRCHOST}" \
    --dbname "${PGSRCDB}" \
    --username postgres \
    --clean --if-exists \
    --no-owner \
    --schema-only \
    --verbose
else
  pg_dump \
    --host "${PGSRCHOST}" \
    --dbname "${PGSRCDB}" \
    --username postgres \
    --clean --if-exists \
    --no-owner \
    --schema-only \
    --table "$1" \
    --verbose
fi
```

---

`get-data-with-copy.sh`

Convenience wrapper around `pg_dump` to generate bulk load `COPY TO` statement(s).

```bash
#!/bin/bash

if [[ -z "${PGSRCHOST}" ]]; then echo "Missing PGSRCHOST"; exit 1; fi
if [[ -z "${PGSRCDB}" ]]; then echo "Missing PGSRCDB"; exit 1; fi

if [[ -z "$1" ]]; then
  pg_dump \
    --host "${PGSRCHOST}" \
    --dbname "${PGSRCDB}" \
    --username postgres \
    --blobs \
    --data-only \
    --verbose
else
  pg_dump \
    --compress 0 \
    --host "${PGSRCHOST}" \
    --dbname "${PGSRCDB}" \
    --username postgres \
    --blobs \
    --data-only \
    --table "$1" \
    --verbose
fi
```

---

`batch-load.sh`

The most complicated script. Takes two parameters: the table to transfer, and
the batch size (how many records per go). There will be a file at
`./.temp/<table-name>.cur` that you can use to track progress, or to edit to
re-start transfer from some particular records (e.g. when back-filling).

```bash
#!/bin/bash

set -e -o pipefail

if [[ -z "${PGSRCHOST}" ]]; then echo "Missing PGSRCHOST"; exit 1; fi
if [[ -z "${PGSRCDB}" ]]; then echo "Missing PGSRCDB"; exit 1; fi
if [[ -z "$1" ]]; then echo "Missing table name and step size"; exit 1; fi
if [[ -z "$2" ]]; then echo "Missing step size"; exit 1; fi

table="$1"
step="$2"

mkdir -p ./.temp

max_id=$(
  psql \
    --host "${PGSRCHOST}"  \
    --dbname "${PGSRCDB}" \
    --username postgres \
    --tuples-only \
    --command "select max(id) from ${table};"
)

if [[ -f "./.temp/${table}.cur" ]]; then
  cur_id=$( cat "./.temp/${table}.cur" )
else
  cur_id=$(
    psql \
      --host "${PGSRCHOST}"  \
      --dbname "${PGSRCDB}" \
      --username postgres \
      --tuples-only \
      --command "select min(id) from ${table};"
  )
fi

while [[  ${cur_id} -le ${max_id} ]]; do
  # Get the batch of data
  query="select * from ${table} where id between ${cur_id} and $(( cur_id + step - 1 ))"
  >&2 printf "\n%s;" "${query}"
  if ! time psql \
      --host "${PGSRCHOST}"  \
      --dbname "${PGSRCDB}" \
      --username postgres \
      --command "copy ( ${query} ) to stdout;" \
    > "./.temp/${table}.dat"
  then
    remaining=5
    while [[ ${remaining} -gt 0 ]]; do
      sleep 5
      remaining=$(( remaining - 1 ))
      rm "./.temp/${table}.dat" || true
      >&2 echo "Retrying (${remaining} attempts remaining)..."
      if ! time psql \
          --host "${PGSRCHOST}"  \
          --dbname "${PGSRCDB}" \
          --username postgres \
          --command "copy ( ${query} ) to stdout;" \
        > "./.temp/${table}.dat"
      then
        if [[ ${remaining} -eq 0 ]]; then
          >&2 echo "Failure (no more retries are remaining)"
          exit 1
        fi
      else
        >&2 echo "Success"
        remaining=0
      fi
    done
  fi

  # Push the batch of data
  if [[ -s "./.temp/${table}.dat" ]]; then
    echo "copy $1 from stdin;"
    cat "./.temp/${table}.dat"
    echo "\."
  fi

  # Increment and remember cursor position
  cur_id=$(( cur_id + step ))
  echo "${cur_id}" > "./.temp/${table}.cur"

  # Refresh max ID (in case it increased meanwhile)
  max_id=$(
    psql \
      --host "${PGSRCHOST}"  \
      --dbname "${PGSRCDB}" \
      --username postgres \
      --tuples-only \
      --command "select max(id) from ${table};"
  )
done

rm "./.temp/${table}.dat" || true

>&2 echo "Done"
```

---

`get-start-id.sh`

A script to query `max(id) + 1` in some of the tables on the target instance.
Helpful for backfilling.

```bash
#!/bin/bash

if [[ -z "${PGDSTHOST}" ]]; then echo "Missing PGDSTHOST"; exit 1; fi
if [[ -z "${PGDSTDB}" ]]; then echo "Missing PGDSTDB"; exit 1; fi
if [[ -z "$1" ]]; then echo "Missing table name"; exit 1; fi

table="$1"

psql \
  --host "${PGDSTHOST}"  \
  --dbname "${PGDSTDB}" \
  --username postgres \
  --tuples-only \
  --command "select (max(id) + 1) from ${table};"
```
