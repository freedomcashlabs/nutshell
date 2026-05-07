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

The image contains `/usr/local/bin/enclava-wait-exec`, because stateful CAP
deployments start the application container immediately and the helper waits
until confidential storage has been prepared before it execs the workload. The
image also contains `/usr/local/bin/app`, which CAP uses as the default
workload command when no explicit command is supplied.

Do not declare Docker `VOLUME` entries for CAP state paths such as `/data`.
CAP mounts those paths from encrypted state volumes. Docker image volumes cause
containerd to create anonymous per-container host paths, which Kata may treat
as direct-assigned volumes instead of the CAP state mount.

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
