.DEFAULT_GOAL := help

# Optional existing operator key; consumed as one quoted SSH argument by the helper.
export CKA_OPERATOR_SSH_KEY

.PHONY: help cka-lab-bootstrap cka-lab-inspect cka-lab-cluster-bootstrap cka-lab-cluster-verify cka-lab-api-start cka-lab-api-verify cka-lab-tunnel-start cka-lab-tunnel-verify

help:
	@printf '%s\n' \
	  'ShadowOps Infra — run from your operator workstation' \
	  '  make cka-lab-bootstrap  Install the bounded rootless CKA runtime on the existing A1' \
	  '  make cka-lab-inspect    Check the installed runtime (read-only)' \
	  '  make cka-lab-cluster-bootstrap  Prepare the private rootless kind cluster (operator only)' \
	  '  make cka-lab-cluster-verify     Verify the existing kind cluster (read-only)' \
	  '  make cka-lab-api-start          Start the admitted private API (no tunnel or public ports)' \
	  '  make cka-lab-api-verify         Verify the private controller and auth boundary (read-only)' \
	  '  make cka-lab-tunnel-start       Start only the prepared lab tunnel (during publication workflow)' \
	  '  make cka-lab-tunnel-verify      Verify connector and public API (read-only)' \
	  '  Optional: CKA_OPERATOR_SSH_KEY=/path/to/existing/key make <target>' \
	  '  Bootstrap prepares the runtime; labs remain disabled until deployment.'

cka-lab-bootstrap:
	bash host/bootstrap-cka-lab-over-ssh.sh bootstrap

cka-lab-inspect:
	bash host/bootstrap-cka-lab-over-ssh.sh inspect

cka-lab-cluster-bootstrap:
	bash host/bootstrap-cka-lab-over-ssh.sh cluster-bootstrap

cka-lab-cluster-verify:
	bash host/bootstrap-cka-lab-over-ssh.sh cluster-verify

cka-lab-api-start:
	bash host/bootstrap-cka-lab-over-ssh.sh api-start

cka-lab-api-verify:
	bash host/bootstrap-cka-lab-over-ssh.sh api-verify

cka-lab-tunnel-start:
	bash host/bootstrap-cka-lab-over-ssh.sh tunnel-start

cka-lab-tunnel-verify:
	bash host/bootstrap-cka-lab-over-ssh.sh tunnel-verify
