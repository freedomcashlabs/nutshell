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

ARG NUTSHELL_BUILD_GIT_SHA=""
ARG NUTSHELL_BUILD_GIT_REF=""
ARG NUTSHELL_BUILD_GITHUB_REPOSITORY=""
ARG NUTSHELL_BUILD_GITHUB_WORKFLOW=""
ARG NUTSHELL_BUILD_GITHUB_RUN_ID=""
ARG NUTSHELL_BUILD_GITHUB_RUN_ATTEMPT=""
ARG NUTSHELL_IMAGE_REF=""

ENV APP_SEED_PATH=/state/app/seed \
    CASHU_DIR=/state/data \
    HOME=/state/data \
    MINT_AUTH_DATABASE=/state/data/mint \
    MINT_BACKEND_BOLT11_SAT=FakeWallet \
    MINT_DATABASE=/state/data/mint \
    MINT_LISTEN_HOST=0.0.0.0 \
    MINT_LISTEN_PORT=3338 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/state/data/tmp \
    XDG_CACHE_HOME=/state/data/.cache \
    NUTSHELL_BUILD_GIT_SHA="${NUTSHELL_BUILD_GIT_SHA}" \
    NUTSHELL_BUILD_GIT_REF="${NUTSHELL_BUILD_GIT_REF}" \
    NUTSHELL_BUILD_GITHUB_REPOSITORY="${NUTSHELL_BUILD_GITHUB_REPOSITORY}" \
    NUTSHELL_BUILD_GITHUB_WORKFLOW="${NUTSHELL_BUILD_GITHUB_WORKFLOW}" \
    NUTSHELL_BUILD_GITHUB_RUN_ID="${NUTSHELL_BUILD_GITHUB_RUN_ID}" \
    NUTSHELL_BUILD_GITHUB_RUN_ATTEMPT="${NUTSHELL_BUILD_GITHUB_RUN_ATTEMPT}" \
    NUTSHELL_IMAGE_REF="${NUTSHELL_IMAGE_REF}"

LABEL org.opencontainers.image.source="${NUTSHELL_BUILD_GITHUB_REPOSITORY}" \
      org.opencontainers.image.revision="${NUTSHELL_BUILD_GIT_SHA}" \
      org.opencontainers.image.ref.name="${NUTSHELL_BUILD_GIT_REF}"

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
    && useradd --uid 10001 --gid 10001 --home-dir /state/data --no-create-home nutshell \
    && mkdir -p /state/app /state/data /state/data/tmp \
    && chmod 0755 /usr/local/bin/app /usr/local/bin/enclava-wait-exec \
    && chown -R 10001:10001 /state

EXPOSE 3338
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/app"]
