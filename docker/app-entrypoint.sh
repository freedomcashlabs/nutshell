#!/bin/sh
set -eu

: "${APP_SEED_PATH:=/state/app/seed}"
: "${MINT_LISTEN_HOST:=0.0.0.0}"
: "${MINT_LISTEN_PORT:=3338}"
: "${MINT_DATABASE:=/data/mint}"
: "${MINT_AUTH_DATABASE:=/data/mint}"
: "${MINT_BACKEND_BOLT11_SAT:=FakeWallet}"
: "${TMPDIR:=/data/tmp}"

export APP_SEED_PATH
export MINT_LISTEN_HOST
export MINT_LISTEN_PORT
export MINT_DATABASE
export MINT_AUTH_DATABASE
export MINT_BACKEND_BOLT11_SAT
export TMPDIR

create_database_dir() {
    case "$1" in
        postgres://*|postgresql://*|sqlite://*)
            return 0
            ;;
    esac
    mkdir -p "$1"
}

derive_private_key() {
    python3 - <<'PY'
import hashlib
import hmac
import os
import sys

seed_path = os.environ.get("APP_SEED_PATH", "/state/app/seed")
if seed_path and os.path.isfile(seed_path):
    with open(seed_path, "rb") as seed_file:
        seed = seed_file.read()
    if not seed:
        sys.exit("APP_SEED_PATH exists but is empty")
elif os.environ.get("NUTSHELL_ALLOW_DEV_SEED") == "1":
    seed = os.environ.get("NUTSHELL_DEV_SEED", "nutshell-dev-seed").encode()
else:
    sys.exit(
        "MINT_PRIVATE_KEY is unset and no app seed is available; "
        "set MINT_PRIVATE_KEY or mount APP_SEED_PATH"
    )

print(
    hmac.new(
        seed,
        b"cashu-nutshell-mint-private-key-v1",
        hashlib.sha256,
    ).hexdigest()
)
PY
}

create_database_dir "$MINT_DATABASE"
create_database_dir "$MINT_AUTH_DATABASE"
mkdir -p "$TMPDIR"

if [ -z "${MINT_PRIVATE_KEY:-}" ]; then
    MINT_PRIVATE_KEY="$(derive_private_key)"
    export MINT_PRIVATE_KEY
fi

if [ "$#" -eq 0 ]; then
    set -- mint
elif [ "${1#-}" != "$1" ]; then
    set -- mint "$@"
fi

exec "$@"
