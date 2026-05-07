FROM python:3.10-slim

ENV APP_SEED_PATH=/state/app/seed \
    CASHU_DIR=/data \
    HOME=/data \
    MINT_BACKEND_BOLT11_SAT=FakeWallet \
    MINT_DATABASE=/data/mint \
    MINT_LISTEN_HOST=0.0.0.0 \
    MINT_LISTEN_PORT=3338 \
    POETRY_HOME=/opt/poetry \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/data/tmp \
    XDG_CACHE_HOME=/data/.cache

ENV PATH="${POETRY_HOME}/bin:${PATH}"

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
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://install.python-poetry.org | python3 - --version 2.3.2

WORKDIR /app
COPY . .
RUN poetry config virtualenvs.create false
RUN poetry install --without dev

RUN groupadd --gid 10001 nutshell \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home nutshell \
    && mkdir -p /data /data/tmp /state/app \
    && chown -R 10001:10001 /data /state \
    && install -m 0755 docker/app-entrypoint.sh /usr/local/bin/app

VOLUME ["/data"]
EXPOSE 3338
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/app"]
