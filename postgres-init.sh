#!/bin/sh
set -eu

: "${BROKER_DB_PASSWORD:?BROKER_DB_PASSWORD must be set for PostgreSQL initialization}"

psql \
  --set=ON_ERROR_STOP=1 \
  --set=broker_password="$BROKER_DB_PASSWORD" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE sealed_arena
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  PASSWORD :'broker_password';

ALTER DATABASE sealed_arena OWNER TO sealed_arena;
SQL
