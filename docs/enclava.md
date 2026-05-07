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

The image contains `/usr/local/bin/app` because CAP starts application
containers through `enclava-wait-exec` and then executes that path after
confidential storage has been prepared.

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
