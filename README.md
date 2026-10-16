# ShadowOps Infra

**Canonical infrastructure control plane for the Matthias ecosystem**:
Chess Studio, Chronicles of Matthias and future services.

Application repositories own **source, tests and immutable build artifacts**.
ShadowOps Infra owns **OCI/Cloudflare infrastructure, deployments, runtime
configuration, promotion/rollback and shared SRE automation** once each
resource's ownership has been explicitly transferred and verified.

**Adoption is incremental, never implied by this README.** Chess Studio's
existing OCI deployments, Cloudflare tunnel, Pages and Render production are
still operated by Chess Studio until a separate proven handoff removes its
old reconciler. Chronicles staging contracts currently remain independent
and are not evidence that any public endpoint is deployed.

Current first step: `.github/workflows/oci-inventory.yml` can inspect the
**existing**, fixed OCI Ampere A1 using ShadowOps's own GitHub Actions
credentials; it never changes OCI resources or workloads. See
[platform ownership](docs/platform-ownership.md).

Deployments require immutable image digests and separately verified staging
accreditation. No production deployment workflow is enabled until all gates
are implemented and tested.
