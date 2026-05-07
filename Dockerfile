FROM python:3.10-slim AS builder

ENV POETRY_HOME=/opt/poetry \
    POETRY_VERSION=2.3.2 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENV PATH="/opt/venv/bin:${POETRY_HOME}/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        curl \
        g++ \
        libffi-dev \
        libpq-dev \
        libtool \
        pkg-config \
        python3-dev \
    && python -m venv /opt/venv \
    && curl -sSL https://install.python-poetry.org | python3 - --version "${POETRY_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN poetry config virtualenvs.create false \
    && VIRTUAL_ENV=/opt/venv poetry install --without dev --no-interaction --no-ansi \
    && find /opt/venv -type d -name '__pycache__' -prune -exec rm -rf '{}' + \
    && find /opt/venv -type f -name '*.pyc' -delete

FROM python:3.10-slim AS runtime

ENV APP_SEED_PATH=/state/app/seed \
    CASHU_DIR=/data \
    HOME=/data \
    MINT_BACKEND_BOLT11_SAT=FakeWallet \
    MINT_DATABASE=/data/mint \
    MINT_LISTEN_HOST=0.0.0.0 \
    MINT_LISTEN_PORT=3338 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/data/tmp \
    XDG_CACHE_HOME=/data/.cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libffi8 \
        libgmp10 \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY cashu ./cashu
COPY pyproject.toml README.md LICENSE.md ./
COPY docker/app-entrypoint.sh /usr/local/bin/app
COPY docker/enclava-wait-exec /usr/local/bin/enclava-wait-exec

RUN groupadd --gid 10001 nutshell \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home nutshell \
    && mkdir -p /data /data/tmp /state/app \
    && chmod 0755 /usr/local/bin/app /usr/local/bin/enclava-wait-exec \
    && chown -R 10001:10001 /data /state

EXPOSE 3338
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/app"]
