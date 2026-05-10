#!/usr/bin/env python3
"""Verify and explain a Nutshell mint deployed on Enclava/CAP.

The verifier intentionally uses only Python's standard library so the proof
package can be downloaded and run without creating a virtualenv.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROOF_PATH = "/.well-known/enclava/proof"
TEE_STATUS_PATH = "/.well-known/confidential/status"
SCHEMA_VERSION = "enclava.nutshell.proof.v1"


@dataclass
class Check:
    ok: bool
    label: str
    detail: str = ""
    warning: bool = False


def print_header(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def print_check(check: Check) -> None:
    marker = "OK" if check.ok else ("WARN" if check.warning else "FAIL")
    print(f"[{marker}] {check.label}")
    if check.detail:
        print(f"     {check.detail}")


def fail(label: str, detail: str = "") -> Check:
    return Check(False, label, detail)


def ok(label: str, detail: str = "") -> Check:
    return Check(True, label, detail)


def warn(label: str, detail: str = "") -> Check:
    return Check(False, label, detail, warning=True)


def normalize_base_url(value: str) -> str:
    value = value.rstrip("/")
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value


def http_get(url: str, *, verify_tls: bool = True, timeout: float = 20.0) -> bytes:
    context = None if verify_tls else ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        headers={"user-agent": "enclava-nutshell-verifier/1"},
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read()


def json_get(url: str, *, verify_tls: bool = True, timeout: float = 20.0) -> dict[str, Any]:
    return json.loads(http_get(url, verify_tls=verify_tls, timeout=timeout).decode())


def get_certificate(base_url: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("certificate verification requires an https URL with a host")
    port = parsed.port or 443
    context = ssl.create_default_context()
    with socket.create_connection((parsed.hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
            cert = tls.getpeercert()
    return cert


def cert_summary(cert: dict[str, Any]) -> str:
    subject = ", ".join("=".join(item) for part in cert.get("subject", []) for item in part)
    issuer = ", ".join("=".join(item) for part in cert.get("issuer", []) for item in part)
    san = ", ".join(value for kind, value in cert.get("subjectAltName", []) if kind == "DNS")
    return (
        f"subject: {subject}\n"
        f"     issuer: {issuer}\n"
        f"     valid: {cert.get('notBefore')} -> {cert.get('notAfter')}\n"
        f"     dns: {san}"
    )


def load_package(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text())


def nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def derive_tee_status_url(base_url: str) -> str | None:
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return None
    if host.endswith(".tee.enclava.dev"):
        tee_host = host
    elif host.endswith(".enclava.dev"):
        tee_host = f"{host.removesuffix('.enclava.dev')}.tee.enclava.dev"
    else:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{tee_host}{port}{TEE_STATUS_PATH}"


def compare_package(proof: dict[str, Any], package: dict[str, Any] | None) -> list[Check]:
    if not package:
        return [warn("No proof package supplied", "Run with --package-file for image/package comparison.")]

    checks: list[Check] = []
    expected_refs = [
        value
        for value in [
            nested(package, "image", "reference"),
            nested(package, "image", "tag_reference"),
        ]
        if value
    ]
    proof_ref = nested(proof, "build", "image_ref")
    if expected_refs and proof_ref:
        checks.append(
            ok("Image reference matches proof package", proof_ref)
            if proof_ref in expected_refs
            else fail(
                "Image reference mismatch",
                f"endpoint={proof_ref} package={', '.join(expected_refs)}",
            )
        )
    else:
        checks.append(warn("Image reference comparison unavailable", "package or endpoint did not include image reference"))

    expected_digest = nested(package, "image", "digest")
    proof_digest = nested(proof, "build", "image_digest")
    if expected_digest and proof_digest:
        checks.append(
            ok("Image digest matches proof package", proof_digest)
            if expected_digest == proof_digest
            else fail("Image digest mismatch", f"endpoint={proof_digest} package={expected_digest}")
        )
    elif expected_digest:
        checks.append(
            warn(
                "Endpoint did not include image digest",
                f"package digest is {expected_digest}; CAP policy/status must bind the image digest.",
            )
        )
    return checks


def verify(base_url: str, package: dict[str, Any] | None, tee_status_url: str | None) -> int:
    failures = 0

    print_header("1. Public HTTPS")
    try:
        cert = get_certificate(base_url)
        print_check(ok("Public TLS certificate is trusted", cert_summary(cert)))
    except Exception as exc:
        print_check(fail("Public TLS certificate verification failed", str(exc)))
        return 1

    try:
        health = http_get(base_url, timeout=20).decode(errors="replace")
        print_check(ok("Public app responded over verified HTTPS", health[:160].replace("\n", "\\n")))
    except urllib.error.HTTPError as exc:
        print_check(ok("Public app responded over verified HTTPS", f"HTTP {exc.code}"))
    except Exception as exc:
        print_check(fail("Public app fetch failed", str(exc)))
        failures += 1

    print_header("2. Nutshell Proof Endpoint")
    proof_url = f"{base_url}{PROOF_PATH}"
    try:
        proof = json_get(proof_url, verify_tls=True)
    except Exception as exc:
        print_check(fail("Failed to fetch proof endpoint", f"{proof_url}: {exc}"))
        return 1

    schema = proof.get("schema_version")
    print_check(
        ok("Proof schema is recognized", schema)
        if schema == SCHEMA_VERSION
        else fail("Unknown proof schema", str(schema))
    )
    print_check(ok("Service", f"{proof.get('service')} {proof.get('service_version')}"))
    print_check(ok("Build source", str(proof.get("build", {}))))

    for check in compare_package(proof, package):
        print_check(check)
        if not check.ok and not check.warning:
            failures += 1

    print_header("3. Enclava TEE Status")
    status_url = tee_status_url or nested(proof, "runtime", "tee_status_url") or derive_tee_status_url(base_url)
    if not status_url:
        print_check(warn("TEE status URL unavailable", "Pass --tee-status-url for non-Enclava hostnames."))
    else:
        try:
            status = json_get(status_url, verify_tls=False, timeout=20)
            print_check(ok("Fetched TEE status", status_url))
            state = status.get("state")
            claims_verified = status.get("claims_verified")
            print_check(
                ok("TEE is unlocked", str(state))
                if state == "unlocked"
                else fail("TEE is not unlocked", str(state))
            )
            print_check(
                ok("TEE claims are verified", str(claims_verified))
                if claims_verified is True
                else fail("TEE claims are not verified", str(claims_verified))
            )
            if state != "unlocked" or claims_verified is not True:
                failures += 1
            image_claim = (
                nested(status, "claims", "image_digest")
                or nested(status, "attestation", "image_digest")
                or nested(status, "init_data_claims", "image_digest")
            )
            expected_digest = nested(package or {}, "image", "digest")
            if image_claim and expected_digest:
                print_check(
                    ok("TEE image claim matches package", image_claim)
                    if expected_digest in image_claim
                    else fail("TEE image claim mismatch", f"claim={image_claim} package={expected_digest}")
                )
            elif expected_digest:
                print_check(
                    warn(
                        "TEE status did not expose image digest",
                        "CAP reported claims_verified=true; use kubectl/CAP attestation records for a lower-level digest proof.",
                    )
                )
        except Exception as exc:
            print_check(fail("Failed to fetch TEE status", f"{status_url}: {exc}"))
            failures += 1

    print_header("Result")
    if failures == 0:
        print_check(ok("Verification completed", "Public TLS, proof endpoint, and available TEE status checks passed."))
        return 0
    print_check(fail("Verification failed", f"{failures} critical check(s) failed."))
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an Enclava-hosted Nutshell mint.")
    parser.add_argument("mint_url", help="Mint URL, for example https://mint.example.enclava.dev")
    parser.add_argument("--package-file", help="Path to enclava-proof-package.json")
    parser.add_argument("--tee-status-url", help="Override the TEE status URL")
    args = parser.parse_args()
    return verify(
        normalize_base_url(args.mint_url),
        load_package(args.package_file),
        args.tee_status_url,
    )


if __name__ == "__main__":
    sys.exit(main())
