.DEFAULT_GOAL := help

# Optional existing operator key; consumed as one quoted SSH argument by the helper.
export CKA_OPERATOR_SSH_KEY

.PHONY: help cka-lab-bootstrap cka-lab-inspect

help:
	@printf '%s\n' \
	  'ShadowOps Infra — run from your operator workstation' \
	  '  make cka-lab-bootstrap  Install the bounded rootless CKA runtime on the existing A1' \
	  '  make cka-lab-inspect    Check the installed runtime (read-only)' \
	  '  Optional: CKA_OPERATOR_SSH_KEY=/path/to/existing/key make <target>' \
	  '  Bootstrap prepares the runtime; labs remain disabled until deployment.'

cka-lab-bootstrap:
	bash host/bootstrap-cka-lab-over-ssh.sh bootstrap

cka-lab-inspect:
	bash host/bootstrap-cka-lab-over-ssh.sh inspect
