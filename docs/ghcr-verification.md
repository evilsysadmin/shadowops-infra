# GHCR image attestation gate

The standalone Chronicles API publishes a signed OCI image from its
`.github/workflows/staging-image.yml` workflow. ShadowOps verifies the
**immutable digest**, source SHA, source ref `refs/heads/main`, and the
**signed workflow identity**, not just self-reported statement metadata.

The local verifier calls `gh attestation verify` using an `oci://` image
reference with a fixed source repository and these mandatory restrictions:
`--signer-workflow`, `--source-digest`, `--source-ref`,
`--predicate-type https://slsa.dev/provenance/v1` and
`--format json`. It then confirms the verified subject digest. The GitHub
CLI validates Sigstore signatures and the signer's certificate identity.

An additional CI job validates this contract **against one already published
historical GHCR image**:
- source commit: `329b6b63244bd1dbe9d504d5a0340a78acf933bb`
- immutable digest: `sha256:3aa847cb86f7e29b1473c6ccaefdceddfcf8e1e5208fb25b84e82ce22f07bd50`
- source publish run: `38808611625`
- GitHub attestation: `56438420`

The example is a pinned **verification fixture**, not a deployment selector or
authorization to promote an old image. Release admission still separately
requires protected main, trusted workflow run identity, required checks,
current commit ancestry and staging smoke.

If the cross-repository GitHub token cannot access the GHCR image or
attestation, CI must fail closed. Grant narrowly scoped GHCR/package read
permissions; **never** disable signature verification, accept untrusted
predicate claims, or move signing secrets into repository files.

No OCI/Render deployment or Chess Studio change is performed here.


## Current OCI A1 candidate verified from protected main

After Chronicles PR #50, the source build publishes a genuine multi-platform
manifest with both `linux/amd64` and `linux/arm64`. ShadowOps live CI
independently reads its OCI manifest and runs the **complete release
accreditation** against:

- Source SHA: `3322ca30f0009f7f371940bf689429e45968e187`
- Source publication workflow run: `38812775390`
- Immutable multiarch manifest digest:
  `sha256:09d91f4a45e1c3b69098526aea5fdff1fe74daf0537ffd22badc5217fbb58634`
- Sigstore provenance: `https://github.com/evilsysadmin/chronicles-of-matthias/attestations/56447971`

The earlier `329b6b6` image is historical and **not suitable for OCI A1**.
This verification is read-only; it does not create a staging server, provision
secrets, register DNS, write a game save or deploy to production.
