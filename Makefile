.DEFAULT_GOAL := help
PYTHON ?= python3
# Canonical operator SSH route to the existing OCI A1 (no OCI CLI session needed).
OCI_SSH_USER ?= ubuntu
OCI_SSH_KEY ?=
OCI_SSH_HOSTNAME ?= ssh-chess-studio-staging.shadowops.dpdns.org
export OCI_SSH_USER OCI_SSH_KEY OCI_SSH_HOSTNAME
export CKA_OPERATOR_SSH_KEY
.PHONY: help cka-retire-host cka-retire-inspect identity-staging-bootstrap \
  oci-a1-ssh-check oci-a1-ssh \
  identity-prod-mongo-host-plan identity-prod-mongo-host-inspect identity-prod-mongo-host-start \
  identity-prod-mongo-material-plan identity-prod-mongo-material-verify \
  identity-prod-mongo-pki-plan identity-prod-mongo-pki-generate \
  identity-prod-mongo-pki-upload-plan identity-prod-mongo-pki-upload-check identity-prod-mongo-pki-upload \
  identity-prod-mongo-pki-host-plan identity-prod-mongo-pki-host-inspect identity-prod-mongo-pki-host-install \
  identity-prod-mongo-start-plan identity-prod-mongo-start-inspect \
  identity-prod-mongo-replica-plan identity-prod-mongo-replica-inspect identity-prod-mongo-replica-init \
  identity-prod-mongo-admin-plan identity-prod-mongo-admin-inspect identity-prod-mongo-admin-create \
  identity-prod-mongo-backup-user-plan identity-prod-mongo-backup-user-inspect identity-prod-mongo-backup-user-create \
  identity-prod-mongo-backup-plan identity-prod-mongo-backup-inspect \
  identity-prod-plan identity-prod-doctor identity-prod-inspect identity-prod-mongo-inspect identity-prod-mongo-apply \
  identity-prod-origin-inspect identity-prod-origin-start identity-prod-origin-stop \
  identity-prod-tunnel-inspect identity-prod-tunnel-start identity-prod-tunnel-stop \
  identity-prod-account-inspect identity-prod-account-create \
  bridgesquad-prod-identity-status bridgesquad-prod-identity-ready bridgesquad-prod-pages-audit \
  bridgesquad-prod-proof-inspect bridgesquad-prod-proof-bind bridgesquad-prod-release-plan
help:
	@printf '%s\n' \
	  'CKA is local-only; repository/history are retained.' \
	  '  make cka-retire-host          Remove only CKA runtime/account/factory on the existing A1' \
	  '  make cka-retire-inspect       Verify CKA is absent from the A1' \
	  '  CKA · retire online resources: run the existing manual GitHub Actions workflow.' \
	  '  Local CKA app: run make up in cka-exam-simulator.' \
	  '' \
	  'OCI A1 access from an operator workstation (Cloudflare Access, no public TCP/22):' \
	  '  make oci-a1-ssh-check      Check exact A1 Cloudflare DNS/TLS and local SSH tools' \
	  '  make oci-a1-ssh            Open interactive SSH to ubuntu on the existing A1' \
	  '       Optional: OCI_SSH_KEY=~/.ssh/my_private_key (private file never uploaded)' \
	  '' \
	  'Bridge Squad / ShadowOps ID production (run on the authorized production host):' \
	  '  make identity-prod-plan       Safe plan; NO Docker, secrets, Cloudflare or Mongo changes' \
	  '  make identity-prod-doctor     Local prerequisite inventory; no secrets printed or commands executed' \
	  '  make identity-prod-inspect    Read-only Mongo + origin preflights (fails if not ready)' \
	  '  make identity-prod-mongo-host-plan | identity-prod-mongo-host-inspect' \
	  '  make identity-prod-mongo-material-plan | identity-prod-mongo-material-verify' \
	  '  make identity-prod-mongo-pki-plan | identity-prod-mongo-pki-generate' \
	  '  make identity-prod-mongo-pki-upload-plan | identity-prod-mongo-pki-upload-check' \
	  '  make identity-prod-mongo-pki-upload Rootless+TTY+ACK, only three files to A1' \
	  '  make identity-prod-mongo-pki-host-plan | identity-prod-mongo-pki-host-inspect' \
	  '  make identity-prod-mongo-pki-host-install  Root+TTY+ACK: three files only on A1' \
	  '       Generate new private CA on a non-root L14 using MONGO_PKI_OUTPUT_DIR' \
	  '       Root-only, read-only cryptographic TLS chain + replica key verification' \
	  '  make identity-prod-mongo-host-start  Root+TTY, confirmation, new/empty Mongo only' \
	  '  make identity-prod-mongo-replica-plan | identity-prod-mongo-replica-inspect' \
	  '  make identity-prod-mongo-replica-init Root+TTY+ACK, exact running product Mongo only' \
	  '  make identity-prod-mongo-admin-plan | identity-prod-mongo-admin-inspect' \
	  '  make identity-prod-mongo-admin-create Root+TTY+ACK, passwordPrompt in mongosh' \
	  '  make identity-prod-mongo-backup-user-plan | identity-prod-mongo-backup-user-inspect' \
	  '  make identity-prod-mongo-backup-user-create Root+TTY+ACK, backup role only' \
	  '  make identity-prod-mongo-backup-plan | identity-prod-mongo-backup-inspect' \
	  '       Offline backup plan and local-only prerequisite check (never uploads)' \
	  '       Validate isolated Mongo host Compose and private TLS file metadata (no deploy)' \
	  '  make identity-prod-mongo-inspect | identity-prod-mongo-apply' \
	  '  make identity-prod-origin-inspect | identity-prod-origin-start | identity-prod-origin-stop' \
	  '  make identity-prod-tunnel-inspect | identity-prod-tunnel-start | identity-prod-tunnel-stop' \
	  '  make identity-prod-account-inspect | identity-prod-account-create' \
	  '       Set IDENTITY_PRODUCTION_ACCOUNT=alias for the two account targets' \
	  '  make bridgesquad-prod-identity-status   Public, read-only status; may be NOT READY' \
	  '  make bridgesquad-prod-identity-ready    Require live public Identity; fails if unready' \
	  '  make bridgesquad-prod-pages-audit       Read-only Pages/DNS/guest audit (Cloudflare GET credential)' \
	  '  make bridgesquad-prod-proof-inspect | bridgesquad-prod-proof-bind' \
	  '       Set BRIDGESQUAD_PAGES_SHA=40hex from LIVE Cloudflare deployment' \
	  '  make bridgesquad-prod-release-plan      Manual protected GitHub Actions release only' \
	  '  Mutations still require their operators root+TTY, private prerequisites and explicit confirmations.'
cka-retire-host:
	bash host/cka-retire-over-ssh.sh retire
cka-retire-inspect:
	bash host/cka-retire-over-ssh.sh inspect
# Legacy entry points cannot recreate retired cloud services.
cka-lab-bootstrap cka-lab-cluster-bootstrap cka-lab-api-start cka-lab-tunnel-start:
	@printf '%s\n' 'CKA online is retired. Use make up in cka-exam-simulator.' >&2
	@exit 1

# Review/install only the fixed Identity staging wrapper and updated consumer schema.
identity-staging-bootstrap:
	bash host/bootstrap-identity-staging-over-ssh.sh

# Operator workstation entrypoints. These only connect to the exact existing
# A1 over the Cloudflare SSH tunnel; they never execute production operators.
oci-a1-ssh-check:
	@$(PYTHON) scripts/oci_a1_ssh.py check

oci-a1-ssh:
	@$(PYTHON) scripts/oci_a1_ssh.py ssh

# Production execution is deliberately LOCAL to the authorized host.
# No SSH fallback, sudo escalation, CI deploy, automated Cloudflare write,
# or relaxation of the explicit confirmations in the existing operators.
# See docs/identity-production-makefile.md for the phase-by-phase runbook.

identity-prod-plan:
	@$(PYTHON) scripts/identity_production_mongo_operator.py plan
	@$(PYTHON) host/identity-production-origin.py plan
	@$(PYTHON) host/identity-production-tunnel.py plan
	@$(PYTHON) host/identity-production-native-account.py plan
	@$(PYTHON) scripts/bridgesquad_production_proof_bind.py plan
	@$(PYTHON) scripts/bridgesquad_production_release.py plan

# Prints only fixed flags: never values, paths, passwords, tokens or Docker output.
identity-prod-doctor:
	@$(PYTHON) scripts/identity_production_doctor.py

# These check only LOCAL prerequisites; they do not SSH to OCI. The
# diagnostic is informational; real operator admission remains authoritative.
identity-prod-inspect:
	@$(PYTHON) scripts/identity_production_doctor.py
	@$(PYTHON) scripts/identity_production_mongo_operator.py inspect
	@$(PYTHON) host/identity-production-origin.py inspect

# Phase 0: isolated Mongo host candidate; never creates resources or starts Docker.
# Local operator workstation only: never via sudo/SSH/CI.
# Local L14 only; upload requires TTY/ACK, pins Cloudflare SSH and never uploads CA private key.
identity-prod-mongo-pki-upload-plan:
	@$(PYTHON) scripts/identity_production_mongo_pki_upload.py plan

identity-prod-mongo-pki-upload-check:
	@$(PYTHON) scripts/identity_production_mongo_pki_upload.py check

identity-prod-mongo-pki-upload:
	@$(PYTHON) scripts/identity_production_mongo_pki_upload.py upload

identity-prod-mongo-pki-plan:
	@$(PYTHON) scripts/identity_production_mongo_pki_generate.py plan

# Explicit A1-only PKI installation from pinned ubuntu staging, never by CI.
identity-prod-mongo-pki-host-plan:
	@$(PYTHON) host/identity-production-mongo-pki-install.py plan

identity-prod-mongo-pki-host-inspect:
	@$(PYTHON) host/identity-production-mongo-pki-install.py inspect

identity-prod-mongo-pki-host-install:
	@$(PYTHON) host/identity-production-mongo-pki-install.py install

identity-prod-mongo-pki-generate:
	@$(PYTHON) scripts/identity_production_mongo_pki_generate.py generate "$${MONGO_PKI_OUTPUT_DIR:?set MONGO_PKI_OUTPUT_DIR to a new absolute path}"

identity-prod-mongo-host-plan:
	@$(PYTHON) scripts/identity_production_mongo_host.py plan

identity-prod-mongo-host-inspect:
	@$(PYTHON) scripts/identity_production_mongo_host.py inspect

# This reads only local private material to verify crypto; no Docker/network.
identity-prod-mongo-material-plan:
	@$(PYTHON) scripts/identity_production_mongo_material.py plan

identity-prod-mongo-material-verify:
	@$(PYTHON) scripts/identity_production_mongo_material.py verify

# Manual first-start only: requires root, TTY, pinned image, verified PKI,
# no pre-existing project/volume/network, and a typed confirmation.
identity-prod-mongo-host-start:
	@$(PYTHON) host/identity-production-mongo-start.py start

# Read-only first-start operator preflight (will reject until PKI exists).
identity-prod-mongo-start-plan:
	@$(PYTHON) host/identity-production-mongo-start.py plan

identity-prod-mongo-start-inspect:
	@$(PYTHON) host/identity-production-mongo-start.py inspect

# Replica init is separate from starting the Mongo process and creating users.
identity-prod-mongo-replica-plan:
	@$(PYTHON) host/identity-production-mongo-replica.py plan

identity-prod-mongo-replica-inspect:
	@$(PYTHON) host/identity-production-mongo-replica.py inspect

identity-prod-mongo-replica-init:
	@$(PYTHON) host/identity-production-mongo-replica.py init

# First user is a separate one-time local operator action. Never chain it.
identity-prod-mongo-admin-plan:
	@$(PYTHON) host/identity-production-mongo-admin.py plan

identity-prod-mongo-admin-inspect:
	@$(PYTHON) host/identity-production-mongo-admin.py inspect

identity-prod-mongo-admin-create:
	@$(PYTHON) host/identity-production-mongo-admin.py create

# First admin must already exist; only an explicitly approved operator creates backup user.
identity-prod-mongo-backup-user-plan:
	@$(PYTHON) host/identity-production-mongo-backup-user.py plan

identity-prod-mongo-backup-user-inspect:
	@$(PYTHON) host/identity-production-mongo-backup-user.py inspect

identity-prod-mongo-backup-user-create:
	@$(PYTHON) host/identity-production-mongo-backup-user.py create

# Off-host encrypted backup is deliberately not a Make mutation target.
identity-prod-mongo-backup-plan:
	@$(PYTHON) scripts/identity_production_mongo_backup.py plan

identity-prod-mongo-backup-inspect:
	@$(PYTHON) scripts/identity_production_mongo_backup.py inspect

identity-prod-mongo-inspect:
	@$(PYTHON) scripts/identity_production_mongo_operator.py inspect

identity-prod-mongo-apply:
	@$(PYTHON) scripts/identity_production_mongo_operator.py apply

identity-prod-origin-inspect:
	@$(PYTHON) host/identity-production-origin.py inspect

identity-prod-origin-start:
	@$(PYTHON) host/identity-production-origin.py start-origin

identity-prod-origin-stop:
	@$(PYTHON) host/identity-production-origin.py stop-origin

identity-prod-tunnel-inspect:
	@$(PYTHON) host/identity-production-tunnel.py inspect

identity-prod-tunnel-start:
	@$(PYTHON) host/identity-production-tunnel.py start-tunnel

identity-prod-tunnel-stop:
	@$(PYTHON) host/identity-production-tunnel.py stop-tunnel

identity-prod-account-inspect:
	@test -n "$$IDENTITY_PRODUCTION_ACCOUNT" || { printf '%s\n' 'Set IDENTITY_PRODUCTION_ACCOUNT=alias (non-secret).' >&2; exit 2; }
	@$(PYTHON) host/identity-production-native-account.py inspect "$$IDENTITY_PRODUCTION_ACCOUNT"

identity-prod-account-create:
	@test -n "$$IDENTITY_PRODUCTION_ACCOUNT" || { printf '%s\n' 'Set IDENTITY_PRODUCTION_ACCOUNT=alias (non-secret).' >&2; exit 2; }
	@$(PYTHON) host/identity-production-native-account.py create "$$IDENTITY_PRODUCTION_ACCOUNT"

# Public probe intentionally separates inspection (exit 0, may say unavailable)
# from the acceptance gate (exit nonzero until the real IdP is ready).
bridgesquad-prod-identity-status:
	@$(PYTHON) scripts/bridgesquad_prod_identity_probe.py inspect

bridgesquad-prod-identity-ready:
	@$(PYTHON) scripts/bridgesquad_prod_identity_probe.py require-public-surface

bridgesquad-prod-pages-audit:
	@$(PYTHON) scripts/bridgesquad_alias_watchdog.py audit

bridgesquad-prod-proof-inspect:
	@test -n "$$BRIDGESQUAD_PAGES_SHA" || { printf '%s\n' 'Set BRIDGESQUAD_PAGES_SHA=40hex from the current Cloudflare canonical deployment.' >&2; exit 2; }
	@$(PYTHON) scripts/bridgesquad_production_proof_bind.py inspect "$$BRIDGESQUAD_PAGES_SHA"

bridgesquad-prod-proof-bind:
	@test -n "$$BRIDGESQUAD_PAGES_SHA" || { printf '%s\n' 'Set BRIDGESQUAD_PAGES_SHA=40hex from the current Cloudflare canonical deployment.' >&2; exit 2; }
	@$(PYTHON) scripts/bridgesquad_production_proof_bind.py bind "$$BRIDGESQUAD_PAGES_SHA"

bridgesquad-prod-release-plan:
	@$(PYTHON) scripts/bridgesquad_production_release.py plan
