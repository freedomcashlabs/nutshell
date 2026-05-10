# Enclava Deployment

This repository publishes the CAP workload image to:

```text
ghcr.io/freedomcashlabs/nutshell
```

CAP deployments must use a digest-pinned image and the GitHub Actions signer
identity for the workflow that signs the image:

```sh
IMAGE="ghcr.io/freedomcashlabs/nutshell@sha256:<digest>"
SIGNER_SUBJECT="https://github.com/freedomcashlabs/nutshell/.github/workflows/docker.yaml@refs/heads/main"

enclava create --image "$IMAGE" --signer-subject "$SIGNER_SUBJECT"
enclava deploy --image "$IMAGE"
```

The first CAP deployment uses password mode so the owner can claim encrypted
storage inside the TEE. After the first deploy is healthy, enable restart
autounlock with `enclava auto-unlock enable`.

The image contains `/usr/local/bin/enclava-wait-exec`, because stateful CAP
deployments start the application container immediately and the helper waits
until confidential storage has been prepared before it execs the workload. The
image also contains `/usr/local/bin/app`; `enclava.toml` pins that argv in the
customer-signed deployment descriptor.

Do not declare Docker `VOLUME` entries for CAP state paths such as `/state`.
CAP exposes decrypted state under `/state` inside the TEE. Docker image volumes
cause containerd to create anonymous per-container host paths, which Kata may
treat as direct-assigned volumes instead of the CAP state mount.

The GHCR package must be publicly readable before deployment. CAP's policy
generation preflight resolves the image manifest from the digest-pinned
reference, and unauthenticated users must be able to perform the same lookup
for the customer-verifiable policy flow. After the first workflow push creates
the package, set `ghcr.io/freedomcashlabs/nutshell` to public in GitHub's
package settings.

At runtime, the entrypoint derives `MINT_PRIVATE_KEY` from the CAP-provided
`APP_SEED_PATH` when `MINT_PRIVATE_KEY` is not explicitly set. The derived key
is not printed. Local Docker smoke tests can use `NUTSHELL_ALLOW_DEV_SEED=1`;
do not set that flag for CAP deployments.

## Verifiable proof package

The image exposes a public proof document at:

```text
/.well-known/enclava/proof
```

and a compatibility-style summary at:

```text
/v1/attestation/info
```

The proof document is intentionally small and safe to expose. It contains the
Nutshell version, the baked GitHub build metadata, the image reference baked
into the container, and the Enclava TEE status URL derived from the public
hostname. It does not expose keys, seeds, invoices, database paths, or secrets.

The Docker workflow uploads an `enclava-proof-package` artifact after a
successful image build. The package contains:

- `enclava-proof-package.json` — image digest, source commit, workflow URL, and
  expected verification endpoints.
- `verify_enclava_nutshell.py` — a dependency-free verifier that prints a
  human-readable proof report.

Example third-party verification:

```sh
python verify_enclava_nutshell.py \
  https://<mint-host> \
  --package-file enclava-proof-package.json
```

The verifier checks:

1. The public mint URL serves over WebPKI-trusted HTTPS.
2. The certificate subject/SAN matches the mint hostname and is issued by a
   trusted CA such as production Let's Encrypt.
3. The proof endpoint is reachable and reports the expected build/package
   metadata.
4. The Enclava TEE status endpoint reports `state=unlocked` and
   `claims_verified=true`.

When CAP exposes lower-level image digest claims in the TEE status document,
the verifier also compares those claims against the proof package image digest.
If the digest claim is not exposed, the verifier prints a warning and still
shows the CAP claim-verification state so an operator can pair it with
Kubernetes/CAP evidence.
