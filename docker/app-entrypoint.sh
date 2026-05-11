#!/bin/sh
set -eu

: "${NUTSHELL_CAP_CONFIG_DIRS:=/run/enclava/config /state/.enclava/config /data/.enclava/config}"
if [ -z "${NUTSHELL_CAP_CONFIG_WAIT_SECONDS+x}" ]; then
    if [ -n "${ENCLAVA_CONTAINER_NAME:-}" ]; then
        NUTSHELL_CAP_CONFIG_WAIT_SECONDS=300
    else
        NUTSHELL_CAP_CONFIG_WAIT_SECONDS=0
    fi
fi
: "${NUTSHELL_REQUIRED_SPARK_STORAGE_DIR:=/state/data/spark}"

is_valid_env_key() {
    case "$1" in
        ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
            return 1
            ;;
    esac
    return 0
}

first_cap_config_dir() {
    for dir in $NUTSHELL_CAP_CONFIG_DIRS; do
        if [ -d "$dir" ]; then
            printf '%s\n' "$dir"
            return 0
        fi
    done
    return 1
}

wait_for_cap_config() {
    seconds="$NUTSHELL_CAP_CONFIG_WAIT_SECONDS"
    case "$seconds" in
        ''|*[!0-9]*)
            echo "NUTSHELL_CAP_CONFIG_WAIT_SECONDS must be an integer" >&2
            exit 1
            ;;
    esac
    [ "$seconds" -gt 0 ] || return 0

    elapsed=0
    while [ "$elapsed" -lt "$seconds" ]; do
        for dir in $NUTSHELL_CAP_CONFIG_DIRS; do
            if [ -f "$dir/.ready" ]; then
                return 0
            fi
        done
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "CAP config was not marked ready after ${seconds}s; continuing with current environment" >&2
}

load_cap_config() {
    dir="$(first_cap_config_dir || true)"
    [ -n "${dir:-}" ] || return 0

    for path in "$dir"/*; do
        [ -f "$path" ] || continue
        key="${path##*/}"
        is_valid_env_key "$key" || continue
        value="$(cat "$path")"
        export "$key=$value"
    done
}

require_nonempty_env() {
    key="$1"
    eval "value=\${$key:-}"
    if [ -z "$value" ]; then
        echo "$key is required when MINT_BACKEND_BOLT11_SAT=SparkWallet" >&2
        exit 1
    fi
}

wait_for_cap_config
load_cap_config

: "${APP_SEED_PATH:=/state/app/seed}"
: "${MINT_LISTEN_HOST:=0.0.0.0}"
: "${MINT_LISTEN_PORT:=3338}"
: "${MINT_DATABASE:=/state/data/mint}"
: "${MINT_AUTH_DATABASE:=/state/data/mint}"
: "${MINT_BACKEND_BOLT11_SAT:=FakeWallet}"
: "${TMPDIR:=/state/data/tmp}"

export APP_SEED_PATH
export MINT_LISTEN_HOST
export MINT_LISTEN_PORT
export MINT_DATABASE
export MINT_AUTH_DATABASE
export MINT_BACKEND_BOLT11_SAT
export TMPDIR

if [ "$MINT_BACKEND_BOLT11_SAT" = "SparkWallet" ]; then
    require_nonempty_env MINT_SPARK_API_KEY
    require_nonempty_env MINT_SPARK_MNEMONIC
    require_nonempty_env MINT_SPARK_STORAGE_DIR

    if [ "$MINT_SPARK_STORAGE_DIR" != "$NUTSHELL_REQUIRED_SPARK_STORAGE_DIR" ]; then
        echo "MINT_SPARK_STORAGE_DIR must be $NUTSHELL_REQUIRED_SPARK_STORAGE_DIR for Enclava Spark deployments" >&2
        exit 1
    fi

    export MINT_SPARK_API_KEY
    export MINT_SPARK_MNEMONIC
    export MINT_SPARK_STORAGE_DIR
fi

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
if [ -n "${MINT_SPARK_STORAGE_DIR:-}" ]; then
    mkdir -p "$MINT_SPARK_STORAGE_DIR"
fi

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
