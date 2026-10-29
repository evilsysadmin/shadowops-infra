# ShadowOps Infra

**Canonical infrastructure control plane for ShadowOps products**: Chess Studio, Chronicles, CKA Simulator and future games/services.

Application repositories own **source, tests and immutable build artifacts**.
ShadowOps Infra owns **OCI/Cloudflare infrastructure, deployments, runtime
configuration, promotion/rollback and shared SRE automation** once each
resource's ownership has been explicitly transferred and verified.

**Adoption is incremental, never implied by this README.** A PR or green CI
does not prove ownership transfer or a running production service.

## P0 — ShadowOps Identity before new CKA authentication

See [platform roadmap](docs/ROADMAP.md), [Identity isolation / migration ADR](docs/identity-platform.md)
and [tracking issue #287](https://github.com/evilsysadmin/shadowops-infra/issues/287).

Target: separate **Identity Staging** and **Identity Production**, each serving
all products of its own environment; no cross-env user DB, signing keys,
cookies, secrets, issuer trust or permissions. **Not deployed yet.**
Use Strangler Fig + Branch by Abstraction + Expand–Contract to migrate the
existing Chess Studio IdP and Chronicles SSO, with rollback and no big-bang cutover.

Authenticated public CKA labs are blocked by this P0, but local kind labs,
CI and the read-only Pages preview remain independent.

Infrastructure handoff procedures remain in
[platform ownership](docs/platform-ownership.md). Release/deploy automation
must continue to pass exact-SHA gates, including validated staging and
production separation.
