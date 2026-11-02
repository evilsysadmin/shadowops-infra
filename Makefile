.DEFAULT_GOAL := help
export CKA_OPERATOR_SSH_KEY
.PHONY: help cka-retire-host cka-retire-inspect identity-staging-bootstrap
help:
	@printf '%s\n' 'CKA is local-only; repository/history are retained.' '  make cka-retire-host     Remove only CKA runtime/account/factory on the existing A1' '  make cka-retire-inspect  Verify CKA is absent from the A1' '  Then run CKA · retire online resources in GitHub Actions (action=retire).' '  Local app: run make up in cka-exam-simulator.'
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
