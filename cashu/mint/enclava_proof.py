import os
import socket
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Request

from ..core.settings import settings

router = APIRouter()

SCHEMA_VERSION = "enclava.nutshell.proof.v1"


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _public_base_url(request: Request) -> str:
    configured = _env("NUTSHELL_PUBLIC_URL")
    if configured:
        return configured.rstrip("/")

    forwarded_proto = request.headers.get("x-forwarded-proto")
    scheme = (forwarded_proto.split(",", 1)[0].strip() if forwarded_proto else "").lower()
    if scheme not in {"http", "https"}:
        scheme = request.url.scheme

    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if not host:
        host = request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _derive_tee_base_url(public_base_url: str) -> str | None:
    configured = _env("ENCLAVA_TEE_BASE_URL")
    if configured:
        return configured.rstrip("/")

    parsed = urlparse(public_base_url)
    hostname = parsed.hostname
    if not hostname:
        return None
    if hostname.endswith(".tee.enclava.dev"):
        tee_host = hostname
    elif hostname.endswith(".enclava.dev"):
        tee_host = f"{hostname.removesuffix('.enclava.dev')}.tee.enclava.dev"
    else:
        return None

    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{tee_host}{port}"


def build_proof_document(request: Request) -> dict:
    public_base_url = _public_base_url(request)
    tee_base_url = _derive_tee_base_url(public_base_url)
    build = {
        "git_sha": _env("NUTSHELL_BUILD_GIT_SHA"),
        "git_ref": _env("NUTSHELL_BUILD_GIT_REF"),
        "github_repository": _env("NUTSHELL_BUILD_GITHUB_REPOSITORY"),
        "github_workflow": _env("NUTSHELL_BUILD_GITHUB_WORKFLOW"),
        "github_run_id": _env("NUTSHELL_BUILD_GITHUB_RUN_ID"),
        "github_run_attempt": _env("NUTSHELL_BUILD_GITHUB_RUN_ATTEMPT"),
        "image_ref": _env("NUTSHELL_IMAGE_REF"),
        "image_digest": _env("NUTSHELL_IMAGE_DIGEST"),
    }
    runtime = {
        "hostname": socket.gethostname(),
        "public_base_url": public_base_url,
        "proof_url": f"{public_base_url}/.well-known/enclava/proof",
        "tee_base_url": tee_base_url,
        "tee_status_url": (
            f"{tee_base_url}/.well-known/confidential/status" if tee_base_url else None
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "service": "nutshell",
        "service_version": settings.version,
        "generated_at_unix": int(time.time()),
        "build": build,
        "runtime": runtime,
        "verification": {
            "public_tls": "Verify this endpoint over WebPKI-trusted HTTPS.",
            "tee_status": "Fetch runtime.tee_status_url and require state=unlocked plus claims_verified=true.",
            "package": "Compare build.image_ref/image_digest against the published Enclava proof package.",
        },
    }


@router.get(
    "/.well-known/enclava/proof",
    name="Enclava proof document",
    include_in_schema=False,
)
async def enclava_proof(request: Request):
    return build_proof_document(request)


@router.get(
    "/v1/attestation/info",
    name="Enclava attestation information",
    include_in_schema=False,
)
async def attestation_info(request: Request):
    proof = build_proof_document(request)
    return {
        "attestation_available": proof["runtime"]["tee_status_url"] is not None,
        "attestation_type": "enclava-cap-sev-snp",
        "proof_url": proof["runtime"]["proof_url"],
        "tee_status_url": proof["runtime"]["tee_status_url"],
        "schema_version": proof["schema_version"],
        "build": proof["build"],
    }
