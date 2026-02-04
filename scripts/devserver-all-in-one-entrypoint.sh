#!/bin/sh
set -eu

# AuthKit Devserver (all-in-one) entrypoint.
# Runs an embedded Postgres and then starts the AuthKit devserver.
#
# Intended for local/E2E use only.

cd /

log() {
  printf '%s\n' "$*" >&2
}

# ---------------------------
# Defaults (zero-config)
# ---------------------------

: "${ENV:=dev}"

: "${POSTGRES_DB:=authkit_db}"
: "${POSTGRES_USER:=admin}"
: "${POSTGRES_PASSWORD:=admin_password}"
export POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD

: "${AUTHKIT_LISTEN_ADDR:=:8080}"
: "${AUTHKIT_ISSUER:=http://issuer:8080}"
: "${AUTHKIT_ISSUED_AUDIENCES:=billing-app}"
: "${AUTHKIT_EXPECTED_AUDIENCES:=${AUTHKIT_ISSUED_AUDIENCES}}"
export AUTHKIT_LISTEN_ADDR AUTHKIT_ISSUER AUTHKIT_ISSUED_AUDIENCES AUTHKIT_EXPECTED_AUDIENCES

# Dev-only minting is enabled by default in this all-in-one image so E2E is zero-config.
: "${AUTHKIT_DEV_MODE:=true}"
: "${AUTHKIT_DEV_MINT_SECRET:=change-me}"
export AUTHKIT_DEV_MODE AUTHKIT_DEV_MINT_SECRET

mkdir -p /.runtime/authkit

shutdown() {
  log "shutting down..."
  if [ "${svc_pid:-}" != "" ] && kill -0 "$svc_pid" 2>/dev/null; then
    kill -TERM "$svc_pid" 2>/dev/null || true
  fi
  if [ "${pg_pid:-}" != "" ] && kill -0 "$pg_pid" 2>/dev/null; then
    kill -TERM "$pg_pid" 2>/dev/null || true
  fi
}

trap shutdown INT TERM

# ---------------------------
# Start embedded Postgres
# ---------------------------

log "starting embedded postgres..."
/usr/local/bin/docker-entrypoint.sh postgres -c listen_addresses='127.0.0.1' >/tmp/postgres.log 2>&1 &
pg_pid=$!

tries=0
until pg_isready -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 240 ]; then
    log "postgres did not become ready (timeout). last logs:"
    tail -n 200 /tmp/postgres.log >&2 || true
    exit 1
  fi
  sleep 0.25
done

if [ "${DB_URL:-}" = "" ]; then
  export DB_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}?sslmode=disable"
fi

if [ "$AUTHKIT_DEV_MODE" = "true" ] && [ "${AUTHKIT_DEV_MINT_SECRET}" = "" ]; then
  log "AUTHKIT_DEV_MODE=true requires AUTHKIT_DEV_MINT_SECRET"
  exit 1
fi

log "authkit devserver all-in-one starting..."
log "  issuer:      ${AUTHKIT_ISSUER}"
log "  listen:      ${AUTHKIT_LISTEN_ADDR}"
log "  audiences:   issued=${AUTHKIT_ISSUED_AUDIENCES} expected=${AUTHKIT_EXPECTED_AUDIENCES}"
log "  jwks:        http://127.0.0.1${AUTHKIT_LISTEN_ADDR}/.well-known/jwks.json"
log "  dev mint:    ${AUTHKIT_DEV_MODE} (secret: ${AUTHKIT_DEV_MINT_SECRET})"
log "  db_url:      ${DB_URL}"
log ""
log "WARNING: this image is for local/E2E use only. do not expose it publicly."

/authkit-devserver serve &
svc_pid=$!

wait "$svc_pid"
code=$?

shutdown
wait "$pg_pid" 2>/dev/null || true

exit "$code"
