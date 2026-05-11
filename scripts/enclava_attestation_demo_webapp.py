#!/usr/bin/env python3
"""Browser demo for Enclava/CAP attestation proof.

This is intentionally dependency-free. It runs a localhost-only web server and
uses the same primitives as verify_enclava_nutshell.py to fetch live evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import verify_enclava_nutshell as verifier


DEFAULT_MINT_URL = "https://tuscany.e9cae29e.enclava.dev"
DEFAULT_MANIFEST_URL = (
    "https://raw.githubusercontent.com/freedomcashlabs/nutshell/main/"
    "deployments/enclava/tuscany.manifest.json"
)


def json_response(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    encoded = json.dumps(body, indent=2).encode()
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("cache-control", "no-store")
    handler.send_header("content-length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def text_from_check(check: verifier.Check) -> dict[str, Any]:
    return {
        "status": "pass" if check.ok else "warn" if check.warning else "fail",
        "label": check.label,
        "detail": check.detail,
    }


def cert_common_name(parts: list[Any]) -> str | None:
    for part in parts:
        for key, value in part:
            if key == "commonName":
                return value
    return None


def public_cert_step(base_url: str) -> dict[str, Any]:
    cert = verifier.get_certificate(base_url)
    parsed = urlparse(base_url)
    issuer = cert_common_name(cert.get("issuer", []))
    subject = cert_common_name(cert.get("subject", []))
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    ok = parsed.hostname in sans and issuer is not None
    return {
        "status": "pass" if ok else "fail",
        "title": "Public HTTPS certificate",
        "claim": "The audience is talking to the public Tuscany mint over WebPKI-trusted HTTPS.",
        "meaning": "This proves the browser-facing endpoint is not a self-signed demo endpoint. It is the public service name protected by a CA-issued certificate.",
        "values": {
            "subject": subject,
            "issuer": issuer,
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
            "dns_names": sans,
        },
    }


def nutshell_step(base_url: str, manifest: dict[str, Any] | None) -> dict[str, Any]:
    info = verifier.json_get(f"{base_url}/v1/info", verify_tls=True, timeout=20)
    keys = verifier.json_get(f"{base_url}/v1/keys", verify_tls=True, timeout=20)
    keysets = keys.get("keysets") or []
    expected_version = verifier.nested(
        manifest or {}, "containers", "web", "expected_service_version"
    )
    ok = bool(info.get("pubkey")) and bool(keysets) and keysets[0].get("active") is True
    if expected_version:
        ok = ok and info.get("version") == expected_version
    return {
        "status": "pass" if ok else "fail",
        "title": "Nutshell mint is live",
        "claim": "The workload behind the public URL is a working Cashu/Nutshell mint.",
        "meaning": "/v1/info exposes the mint identity and /v1/keys exposes an active signing keyset. This is the app-level proof that Nutshell itself is serving.",
        "values": {
            "name": info.get("name"),
            "version": info.get("version"),
            "expected_version": expected_version,
            "mint_pubkey": info.get("pubkey"),
            "active_keysets": len([item for item in keysets if item.get("active") is True]),
            "first_keyset_id": keysets[0].get("id") if keysets else None,
        },
    }


def proof_endpoint_step(base_url: str) -> dict[str, Any]:
    proof = verifier.json_get(f"{base_url}{verifier.PROOF_PATH}", verify_tls=True, timeout=20)
    ok = proof.get("schema_version") == verifier.SCHEMA_VERSION
    return {
        "status": "pass" if ok else "fail",
        "title": "Nutshell build proof endpoint",
        "claim": "The app reports the GitHub build metadata baked into the running container.",
        "meaning": "This gives the audience a public, app-served record of the source commit, workflow, and image reference that produced the workload.",
        "values": {
            "schema": proof.get("schema_version"),
            "service": proof.get("service"),
            "service_version": proof.get("service_version"),
            "git_sha": verifier.nested(proof, "build", "git_sha"),
            "github_repository": verifier.nested(proof, "build", "github_repository"),
            "github_workflow": verifier.nested(proof, "build", "github_workflow"),
            "github_run_id": verifier.nested(proof, "build", "github_run_id"),
            "image_ref": verifier.nested(proof, "build", "image_ref"),
        },
    }


def tee_status_step(manifest: dict[str, Any] | None, base_url: str) -> dict[str, Any]:
    status_url = (
        verifier.nested(manifest or {}, "deployment", "tee_status_url")
        or verifier.derive_tee_status_url(base_url)
    )
    status = verifier.json_get(status_url, verify_tls=False, timeout=20)
    ok = (
        status.get("state") == "unlocked"
        and status.get("claims_verified") is True
        and not status.get("error")
    )
    return {
        "status": "pass" if ok else "fail",
        "title": "TEE control status",
        "claim": "The confidential workload is unlocked and its runtime claims are verified.",
        "meaning": "Unlocked means the owner-sealed state path completed successfully. claims_verified=true means CAP accepted the confidential runtime claims for this instance.",
        "values": {
            "status_url": status_url,
            "state": status.get("state"),
            "claims_verified": status.get("claims_verified"),
            "ciphertext_backend": status.get("ciphertext_backend"),
            "tenant_id": status.get("tenant_id"),
            "instance_id": status.get("instance_id"),
            "tenant_instance_identity_hash": status.get("tenant_instance_identity_hash"),
            "error": status.get("error"),
        },
    }


def public_leaf_spki_sha256(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.hostname:
        raise ValueError("URL has no host")
    context = ssl.create_default_context()
    with verifier.socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
            der_cert = tls.getpeercert(binary_form=True)
    cert = ssl.DER_cert_to_PEM_cert(der_cert).encode()
    pubkey = subprocess.check_output(["openssl", "x509", "-pubkey", "-noout"], input=cert)
    spki_der = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pubkey)
    return hashlib.sha256(spki_der).hexdigest()


def fresh_attestation_step(base_url: str, manifest: dict[str, Any] | None) -> dict[str, Any]:
    public_host = urlparse(base_url).hostname or ""
    attestation_url = (
        verifier.nested(manifest or {}, "deployment", "attestation_url")
        or f"{base_url}/v1/attestation"
    )
    expected_spki = verifier.nested(
        manifest or {}, "expected_runtime", "attestation_proxy_tls_leaf_spki_sha256"
    )
    if not expected_spki:
        tee_status_url = (
            verifier.nested(manifest or {}, "deployment", "tee_status_url")
            or verifier.derive_tee_status_url(base_url)
        )
        expected_spki = verifier.spki_sha256_for_host(
            tee_status_url.removesuffix(verifier.TEE_STATUS_PATH), verify_tls=False
        )

    nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce).decode()
    query = urlencode(
        {
            "nonce": nonce_b64,
            "domain": public_host,
            "leaf_spki_sha256": expected_spki,
        }
    )
    receipt = verifier.json_get(f"{attestation_url}?{query}", verify_tls=True, timeout=30)
    binding = receipt.get("runtime_data_binding") or {}
    claims = receipt.get("claims") or {}
    claims_meta = receipt.get("claims_meta") or {}
    report_data = verifier.nested(receipt, "evidence", "json", "attestation_report", "report_data")
    receipt_pubkey_hash = binding.get("receipt_pubkey_sha256")
    expected_report_data = None
    actual_report_data = None
    if isinstance(report_data, list) and isinstance(receipt_pubkey_hash, str):
        actual_report_data = bytes(report_data).decode()
        transcript_hash = verifier.ce_v1_hash(
            [
                ("purpose", b"enclava-tee-tls-v1"),
                ("domain", public_host.encode()),
                ("nonce", nonce),
                ("leaf_spki_sha256", bytes.fromhex(expected_spki)),
            ]
        )
        expected_report_data = verifier.ce_v1_hash(
            [
                ("purpose", b"enclava-tee-report-data-v1"),
                ("transcript_hash", transcript_hash),
                ("receipt_pubkey_sha256", bytes.fromhex(receipt_pubkey_hash)),
            ]
        ).hex()
    ok = (
        receipt.get("attestation_type") == "coco-sev-snp"
        and receipt.get("nonce") == nonce_b64
        and binding.get("domain") == public_host
        and binding.get("leaf_spki_sha256") == expected_spki
        and verifier.nested(claims, "tee") == "sev-snp"
        and claims_meta.get("aa_token_measurement_matches_evidence") is True
        and actual_report_data == expected_report_data
    )
    return {
        "status": "pass" if ok else "fail",
        "title": "Fresh SEV-SNP attestation",
        "claim": "A new nonce-bound AMD SEV-SNP attestation was generated for this demo request.",
        "meaning": "The random nonce prevents replay. REPORT_DATA binds that nonce to the public domain, the TEE TLS key, and the in-TEE receipt key, so the evidence is tied to this live endpoint.",
        "values": {
            "attestation_type": receipt.get("attestation_type"),
            "tee": verifier.nested(claims, "tee"),
            "nonce": nonce_b64,
            "domain": binding.get("domain"),
            "tee_tls_leaf_spki_sha256": binding.get("leaf_spki_sha256"),
            "receipt_pubkey_sha256": receipt_pubkey_hash,
            "measurement": claims.get("measurement"),
            "init_data_hash": verifier.nested(claims, "workload", "init_data_hash"),
            "aa_token_measurement_matches_evidence": claims_meta.get(
                "aa_token_measurement_matches_evidence"
            ),
            "report_data_from_snp_report": actual_report_data,
            "report_data_recomputed_by_python": expected_report_data,
            "server_verdict": verifier.nested(receipt, "server_verification", "verdict"),
            "server_warnings": verifier.nested(receipt, "server_verification", "warnings"),
        },
    }


def manifest_step(manifest: dict[str, Any] | None, live_kubernetes: bool) -> dict[str, Any]:
    checks = verifier.compare_manifest_to_live(manifest, live_kubernetes)
    ok = all(check.ok or check.warning for check in checks)
    return {
        "status": "pass" if ok else "fail",
        "title": "Published manifest matches live pod",
        "claim": "The repo-published manifest is compared against the actual Kubernetes pod.",
        "meaning": "This connects the public GitHub proof anchor to the concrete images and readiness state running in the cluster.",
        "values": {
            "checks": [text_from_check(check) for check in checks],
        },
    }


def collect_demo(base_url: str, manifest_url: str | None, live_kubernetes: bool) -> dict[str, Any]:
    base_url = verifier.normalize_base_url(base_url)
    manifest = verifier.load_json_resource(manifest_url)
    steps = [
        public_cert_step(base_url),
        nutshell_step(base_url, manifest),
        proof_endpoint_step(base_url),
        tee_status_step(manifest, base_url),
        fresh_attestation_step(base_url, manifest),
        manifest_step(manifest, live_kubernetes),
    ]
    return {
        "ok": all(step["status"] == "pass" for step in steps),
        "mint_url": base_url,
        "manifest_url": manifest_url,
        "steps": steps,
    }


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enclava TEE Attestation Demo</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #15202b;
      --muted: #5c6b7a;
      --line: #d8dee8;
      --pass: #13795b;
      --warn: #9a6700;
      --fail: #b42318;
      --accent: #2457d6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      padding: 28px 32px 18px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }
    .sub { color: var(--muted); max-width: 920px; line-height: 1.45; }
    .controls {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) minmax(320px, 1.4fr) auto;
      gap: 12px;
      padding: 18px 32px;
      align-items: end;
      background: #fff;
      border-bottom: 1px solid var(--line);
    }
    label { display: grid; gap: 6px; font-size: 13px; color: var(--muted); }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      font-size: 14px;
      color: var(--ink);
      background: #fff;
    }
    button {
      height: 40px;
      padding: 0 16px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      font-weight: 650;
      cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: wait; }
    main { padding: 24px 32px 40px; }
    .summary {
      display: flex;
      gap: 12px;
      align-items: center;
      margin-bottom: 18px;
      color: var(--muted);
    }
    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 13px;
      font-weight: 700;
      color: white;
      background: var(--muted);
    }
    .pill.pass { background: var(--pass); }
    .pill.fail { background: var(--fail); }
    .timeline {
      display: grid;
      gap: 14px;
      max-width: 1180px;
    }
    .step {
      display: grid;
      grid-template-columns: 160px minmax(0, 1fr);
      gap: 18px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }
    .status {
      display: inline-flex;
      width: fit-content;
      padding: 5px 9px;
      border-radius: 6px;
      color: white;
      text-transform: uppercase;
      font-weight: 750;
      font-size: 12px;
    }
    .status.pass { background: var(--pass); }
    .status.warn { background: var(--warn); }
    .status.fail { background: var(--fail); }
    h2 { margin: 0 0 8px; font-size: 20px; }
    p { margin: 0 0 10px; line-height: 1.45; }
    .claim { font-weight: 650; }
    .meaning { color: var(--muted); }
    dl {
      display: grid;
      grid-template-columns: minmax(180px, 260px) minmax(0, 1fr);
      gap: 8px 14px;
      margin: 14px 0 0;
      padding-top: 14px;
      border-top: 1px solid var(--line);
    }
    dt { color: var(--muted); font-size: 13px; }
    dd { margin: 0; min-width: 0; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .check-list { display: grid; gap: 8px; }
    .check-row { padding: 8px; border: 1px solid var(--line); border-radius: 6px; }
    .error {
      padding: 14px;
      border: 1px solid #f2b8b5;
      background: #fff2f1;
      color: var(--fail);
      border-radius: 8px;
      white-space: pre-wrap;
    }
    @media (max-width: 820px) {
      .controls { grid-template-columns: 1fr; }
      .step { grid-template-columns: 1fr; }
      dl { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Enclava TEE Attestation Demo</h1>
    <div class="sub">A live, nonce-bound proof that the public Nutshell mint is running behind an Enclava confidential workload, with the values decoded into human terms.</div>
  </header>
  <section class="controls">
    <label>Mint URL
      <input id="mintUrl" value="__MINT_URL__">
    </label>
    <label>Published manifest
      <input id="manifestUrl" value="__MANIFEST_URL__">
    </label>
    <button id="runBtn">Run live proof</button>
  </section>
  <main>
    <div id="output" class="summary">Click “Run live proof” to fetch fresh evidence.</div>
  </main>
  <script>
    const output = document.getElementById('output');
    const runBtn = document.getElementById('runBtn');
    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    }
    function renderValue(value) {
      if (Array.isArray(value)) {
        if (value.length && value[0] && typeof value[0] === 'object' && 'label' in value[0]) {
          return '<div class="check-list">' + value.map(item =>
            `<div class="check-row"><span class="status ${esc(item.status)}">${esc(item.status)}</span> ${esc(item.label)}<br><small>${esc(item.detail)}</small></div>`
          ).join('') + '</div>';
        }
        return esc(JSON.stringify(value));
      }
      if (value && typeof value === 'object') return esc(JSON.stringify(value));
      return esc(value);
    }
    function render(data) {
      const passCount = data.steps.filter(step => step.status === 'pass').length;
      const header = `<div class="summary"><span class="pill ${data.ok ? 'pass' : 'fail'}">${data.ok ? 'PASS' : 'CHECK'}</span><span>${passCount}/${data.steps.length} proof stages passed for ${esc(data.mint_url)}</span></div>`;
      const steps = data.steps.map(step => {
        const values = Object.entries(step.values || {}).map(([key, value]) => `<dt>${esc(key)}</dt><dd>${renderValue(value)}</dd>`).join('');
        return `<article class="step">
          <div><span class="status ${esc(step.status)}">${esc(step.status)}</span></div>
          <div>
            <h2>${esc(step.title)}</h2>
            <p class="claim">${esc(step.claim)}</p>
            <p class="meaning">${esc(step.meaning)}</p>
            <dl>${values}</dl>
          </div>
        </article>`;
      }).join('');
      output.className = '';
      output.innerHTML = header + `<section class="timeline">${steps}</section>`;
    }
    async function runProof() {
      runBtn.disabled = true;
      output.className = 'summary';
      output.textContent = 'Fetching live TLS, Nutshell, TEE status, SNP attestation, and Kubernetes evidence...';
      const params = new URLSearchParams({
        mint_url: document.getElementById('mintUrl').value,
        manifest_url: document.getElementById('manifestUrl').value,
      });
      try {
        const res = await fetch('/api/proof?' + params.toString(), {cache: 'no-store'});
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || JSON.stringify(data));
        render(data);
      } catch (err) {
        output.className = 'error';
        output.textContent = err.stack || String(err);
      } finally {
        runBtn.disabled = false;
      }
    }
    runBtn.addEventListener('click', runProof);
  </script>
</body>
</html>
"""


class DemoHandler(BaseHTTPRequestHandler):
    mint_url = DEFAULT_MINT_URL
    manifest_url = DEFAULT_MANIFEST_URL
    live_kubernetes = True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = (
                HTML.replace("__MINT_URL__", html.escape(self.mint_url))
                .replace("__MANIFEST_URL__", html.escape(self.manifest_url))
                .encode()
            )
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/proof":
            params = parse_qs(parsed.query)
            mint_url = params.get("mint_url", [self.mint_url])[0]
            manifest_url = params.get("manifest_url", [self.manifest_url])[0]
            try:
                proof = collect_demo(mint_url, manifest_url, self.live_kubernetes)
                json_response(self, 200, proof)
            except Exception as exc:
                json_response(self, 500, {"error": f"{type(exc).__name__}: {exc}"})
            return
        self.send_error(404)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local Enclava attestation demo web app.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--mint-url", default=DEFAULT_MINT_URL)
    parser.add_argument("--manifest-url", default=DEFAULT_MANIFEST_URL)
    parser.add_argument("--no-live-kubernetes", action="store_true")
    args = parser.parse_args()

    DemoHandler.mint_url = args.mint_url
    DemoHandler.manifest_url = args.manifest_url
    DemoHandler.live_kubernetes = not args.no_live_kubernetes
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"Serving demo on http://{args.host}:{args.port}")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
