# Chronicles A1 first-boot authority — one-shot observation

ShadowOps' trusted-main one-shot observation lives in GitHub Actions run
[38885330529](https://github.com/evilsysadmin/shadowops-infra/actions/runs/38885330529).

The command is read-only; it checks Docker daemon accessibility from Oracle's
unprivileged Run Command account, presence of a ShadowOps Git checkout, the
dedicated Chronicles web deploy wrapper, and the GitHub CLI. It does not expose
user names, host environment, Docker container data or credential values.

The temporary credential-backed `push` gate was retired immediately after
the one-shot run was dispatched. The capability job is manual-only on trusted
ShadowOps `main` from this point forward. PR and push checks run mocks only.

**Do not infer deployment authority from working OCI credentials.** If the
agent cannot access Docker or the dedicated wrapper is absent, installation
of an independently reviewed limited Chronicle-only host deploy mechanism
is a prerequisite to launch. Never grant unrestricted `sudo` or add `ocarun`
to the Docker group to work around that boundary.

Do not claim Chronicles is running from a green host check alone.
