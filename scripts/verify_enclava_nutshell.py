#!/usr/bin/env python3
"""Verify and explain a Nutshell mint deployed on Enclava/CAP.

The verifier intentionally uses only Python's standard library so the proof
package can be downloaded and run without creating a virtualenv.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

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


def load_json_resource(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        return json.loads(http_get(value, verify_tls=True).decode())
    return json.loads(Path(value).read_text())


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


def ce_v1_hash(records: list[tuple[str, bytes]]) -> bytes:
    payload = bytearray()
    for label, value in records:
        label_bytes = label.encode()
        payload.extend(len(label_bytes).to_bytes(2, "big"))
        payload.extend(label_bytes)
        payload.extend(len(value).to_bytes(4, "big"))
        payload.extend(value)
    return hashlib.sha256(payload).digest()


def spki_sha256_for_host(base_url: str, *, verify_tls: bool) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("SPKI verification requires an https URL with a host")
    port = parsed.port or 443
    context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    with socket.create_connection((parsed.hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
            der_cert = tls.getpeercert(binary_form=True)
    cert = ssl.DER_cert_to_PEM_cert(der_cert).encode()
    pubkey = subprocess.check_output(["openssl", "x509", "-pubkey", "-noout"], input=cert)
    spki_der = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pubkey)
    return hashlib.sha256(spki_der).hexdigest()


def verify_fresh_attestation(base_url: str, manifest: dict[str, Any] | None) -> list[Check]:
    checks: list[Check] = []
    public_host = urlparse(base_url).hostname or ""
    attestation_url = nested(manifest or {}, "deployment", "attestation_url") or f"{base_url}/v1/attestation"
    tee_status_url = nested(manifest or {}, "deployment", "tee_status_url") or derive_tee_status_url(base_url)
    expected_spki = nested(manifest or {}, "expected_runtime", "attestation_proxy_tls_leaf_spki_sha256")
    if not expected_spki:
        if not tee_status_url:
            return [warn("Fresh attestation skipped", "No TEE status URL or expected TEE TLS SPKI was available.")]
        tee_base = tee_status_url.removesuffix(TEE_STATUS_PATH)
        try:
            expected_spki = spki_sha256_for_host(tee_base, verify_tls=False)
        except Exception as exc:
            return [fail("Could not calculate TEE TLS SPKI", str(exc))]

    nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce).decode()
    query = urlencode(
        {
            "nonce": nonce_b64,
            "domain": public_host,
            "leaf_spki_sha256": expected_spki,
        }
    )
    try:
        receipt = json_get(f"{attestation_url}?{query}", verify_tls=True, timeout=30)
    except Exception as exc:
        return [fail("Fresh attestation request failed", str(exc))]

    attestation_type = receipt.get("attestation_type")
    checks.append(
        ok("Attestation profile is SEV-SNP", attestation_type)
        if attestation_type == "coco-sev-snp"
        else fail("Unexpected attestation profile", str(attestation_type))
    )
    checks.append(
        ok("Nonce is echoed by attestation response", nonce_b64)
        if receipt.get("nonce") == nonce_b64
        else fail("Nonce mismatch", f"sent={nonce_b64} received={receipt.get('nonce')}")
    )

    binding = receipt.get("runtime_data_binding") or {}
    checks.append(
        ok("Attestation is bound to the public domain", public_host)
        if binding.get("domain") == public_host
        else fail("Attestation domain mismatch", str(binding.get("domain")))
    )
    checks.append(
        ok("Attestation is bound to the TEE TLS leaf key", expected_spki)
        if binding.get("leaf_spki_sha256") == expected_spki
        else fail("TEE TLS SPKI mismatch", str(binding.get("leaf_spki_sha256")))
    )

    claims = receipt.get("claims") or {}
    checks.append(
        ok("TEE claim says sev-snp", str(nested(claims, "tee")))
        if nested(claims, "tee") == "sev-snp"
        else fail("TEE claim was not sev-snp", str(nested(claims, "tee")))
    )
    measurement = claims.get("measurement")
    checks.append(
        ok("TEE measurement is present", str(measurement))
        if isinstance(measurement, str) and len(measurement) == 96
        else fail("TEE measurement missing or malformed", str(measurement))
    )
    claims_meta = receipt.get("claims_meta") or {}
    checks.append(
        ok("AA token measurement matches evidence", "true")
        if claims_meta.get("aa_token_measurement_matches_evidence") is True
        else fail("AA token measurement did not match evidence", json.dumps(claims_meta, sort_keys=True))
    )

    report_data = nested(receipt, "evidence", "json", "attestation_report", "report_data")
    receipt_pubkey_hash = binding.get("receipt_pubkey_sha256")
    if isinstance(report_data, list) and isinstance(receipt_pubkey_hash, str):
        try:
            report_data_text = bytes(report_data).decode()
            transcript_hash = ce_v1_hash(
                [
                    ("purpose", b"enclava-tee-tls-v1"),
                    ("domain", public_host.encode()),
                    ("nonce", nonce),
                    ("leaf_spki_sha256", bytes.fromhex(expected_spki)),
                ]
            )
            expected_binding = ce_v1_hash(
                [
                    ("purpose", b"enclava-tee-report-data-v1"),
                    ("transcript_hash", transcript_hash),
                    ("receipt_pubkey_sha256", bytes.fromhex(receipt_pubkey_hash)),
                ]
            ).hex()
            checks.append(
                ok("SNP REPORT_DATA binds nonce, domain, TLS key, and receipt key", expected_binding)
                if report_data_text == expected_binding
                else fail("SNP REPORT_DATA binding mismatch", f"report={report_data_text} expected={expected_binding}")
            )
        except Exception as exc:
            checks.append(fail("Could not verify SNP REPORT_DATA binding", str(exc)))
    else:
        checks.append(fail("SNP REPORT_DATA missing", "attestation report did not expose report_data"))

    verdict = nested(receipt, "server_verification", "verdict")
    if verdict == "verified":
        checks.append(ok("Server-side attestation policy verdict", verdict))
    elif verdict == "inconclusive":
        checks.append(
            warn(
                "Server-side attestation policy verdict is inconclusive",
                "Fresh SNP evidence and REPORT_DATA binding verified; image digest claim is not exposed by AA token.",
            )
        )
    else:
        checks.append(fail("Server-side attestation policy verdict", str(verdict)))
    return checks


def normalize_image_ref(value: str) -> str:
    return value.replace(":24h@", "@")


def compare_manifest_to_live(manifest: dict[str, Any] | None, live_kubernetes: bool) -> list[Check]:
    if not manifest:
        return [warn("No deployment manifest supplied", "Run with --deployment-manifest-url for live-image comparison.")]
    checks: list[Check] = []
    if not live_kubernetes:
        return [warn("Live Kubernetes comparison skipped", "Run with --live-kubernetes to compare the published manifest to the running pod.")]

    namespace = nested(manifest, "deployment", "namespace")
    pod = nested(manifest, "deployment", "pod")
    if not namespace or not pod:
        return [fail("Deployment manifest missing namespace/pod", json.dumps(nested(manifest, "deployment") or {}))]
    try:
        pod_json = subprocess.check_output(
            ["ssh", "control1.encl", f"kubectl -n {namespace} get pod {pod} -o json"],
            text=True,
            timeout=30,
        )
        live = json.loads(pod_json)
    except Exception as exc:
        return [fail("Could not inspect live Kubernetes pod", str(exc))]

    expected = manifest.get("containers") or {}
    live_spec = {item["name"]: item.get("image") for item in nested(live, "spec", "containers") or []}
    live_status = {
        item["name"]: {
            "ready": item.get("ready"),
            "imageID": item.get("imageID"),
        }
        for item in nested(live, "status", "containerStatuses") or []
    }
    for name, spec in expected.items():
        expected_image = spec.get("image")
        expected_image_id = spec.get("image_id", expected_image)
        actual_image = live_spec.get(name)
        actual_image_id = (live_status.get(name) or {}).get("imageID")
        ready = (live_status.get(name) or {}).get("ready")
        checks.append(
            ok(f"Live container {name} image matches manifest", actual_image or "")
            if actual_image == expected_image
            else fail(f"Live container {name} image mismatch", f"live={actual_image} manifest={expected_image}")
        )
        if expected_image_id and actual_image_id:
            checks.append(
                ok(f"Live container {name} imageID matches manifest", actual_image_id)
                if normalize_image_ref(actual_image_id) == normalize_image_ref(expected_image_id)
                else fail(
                    f"Live container {name} imageID mismatch",
                    f"live={actual_image_id} manifest={expected_image_id}",
                )
            )
        checks.append(
            ok(f"Live container {name} is ready", "true")
            if ready is True
            else fail(f"Live container {name} is not ready", str(ready))
        )
    return checks


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


def verify(
    base_url: str,
    package: dict[str, Any] | None,
    tee_status_url: str | None,
    deployment_manifest: dict[str, Any] | None,
    live_kubernetes: bool,
) -> int:
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

    try:
        mint_info = json_get(f"{base_url}/v1/info", verify_tls=True, timeout=20)
        version = mint_info.get("version")
        name = mint_info.get("name")
        pubkey = mint_info.get("pubkey")
        expected_version = nested(deployment_manifest or {}, "containers", "web", "expected_service_version")
        print_check(
            ok("Nutshell /v1/info returned mint identity", f"{name} {version}, pubkey={pubkey}")
            if name and version and pubkey
            else fail("Nutshell /v1/info did not include mint identity", json.dumps(mint_info, sort_keys=True))
        )
        if expected_version:
            print_check(
                ok("Nutshell version matches published manifest", version)
                if version == expected_version
                else fail("Nutshell version mismatch", f"endpoint={version} manifest={expected_version}")
            )
    except Exception as exc:
        print_check(fail("Nutshell /v1/info failed", str(exc)))
        failures += 1

    try:
        keys = json_get(f"{base_url}/v1/keys", verify_tls=True, timeout=20)
        keysets = keys.get("keysets") or []
        print_check(
            ok("Nutshell /v1/keys returned active keyset", f"keysets={len(keysets)}")
            if keysets and keysets[0].get("active") is True
            else fail("Nutshell /v1/keys did not return an active keyset", json.dumps(keys, sort_keys=True))
        )
    except Exception as exc:
        print_check(fail("Nutshell /v1/keys failed", str(exc)))
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
    status_url = (
        tee_status_url
        or nested(deployment_manifest or {}, "deployment", "tee_status_url")
        or nested(proof, "runtime", "tee_status_url")
        or derive_tee_status_url(base_url)
    )
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

    print_header("4. Fresh TEE Attestation")
    for check in verify_fresh_attestation(base_url, deployment_manifest):
        print_check(check)
        if not check.ok and not check.warning:
            failures += 1

    print_header("5. Published Manifest vs Live Pod")
    for check in compare_manifest_to_live(deployment_manifest, live_kubernetes):
        print_check(check)
        if not check.ok and not check.warning:
            failures += 1

    print_header("Result")
    if failures == 0:
        print_check(ok("Verification completed", "Public TLS, proof endpoint, TEE status, fresh attestation, and enabled manifest checks passed."))
        return 0
    print_check(fail("Verification failed", f"{failures} critical check(s) failed."))
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an Enclava-hosted Nutshell mint.")
    parser.add_argument("mint_url", help="Mint URL, for example https://mint.example.enclava.dev")
    parser.add_argument("--package-file", help="Path to enclava-proof-package.json")
    parser.add_argument("--deployment-manifest-url", help="Local path or HTTPS URL for a published deployment manifest")
    parser.add_argument("--live-kubernetes", action="store_true", help="Compare the deployment manifest to the live Kubernetes pod via ssh control1.encl")
    parser.add_argument("--tee-status-url", help="Override the TEE status URL")
    args = parser.parse_args()
    return verify(
        normalize_base_url(args.mint_url),
        load_package(args.package_file),
        args.tee_status_url,
        load_json_resource(args.deployment_manifest_url),
        args.live_kubernetes,
    )


if __name__ == "__main__":
    sys.exit(main())
