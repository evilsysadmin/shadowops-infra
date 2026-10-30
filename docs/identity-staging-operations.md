# Identity staging operational handoff

The executable/image is delivered by [#324](https://github.com/evilsysadmin/shadowops-infra/pull/324).
This handoff defines a separate `shadowops-identity-staging` project, a persistent
Mongo replica, narrowly scoped service credentials, private TLS and a dedicated
Cloudflare tunnel. It does not activate Chronicles or claim a public login.

The staging operator bundle is generated once in Actions and retained as
`identity-staging-operator-bundle` in OCI Vault. It has independent Mongo root
and application credentials, replica key, private CA, service certificate,
JWT signing seed, Chronicles service credential and backup encryption key.
Retries preserve account/signing/backup material; an unreadable or invalid
existing Vault entry fails rather than generating replacement keys. Tunnel
credential rotation updates only that field. No values appear in logs/artifacts.
The Vault bundle must never be mounted whole in either service.

The runtime receives only its app Mongo URI, public Mongo CA, web TLS keypair,
JWT signing seed and the registered Chronicles credential. Mongo receives only
its replica/TLS files. Cloudflared receives its own token and public CA; its
origin uses HTTPS with a pinned hostname and CA, never `noTLSVerify`.
[Cloudflare origin parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/)
document this trust configuration. DNS refuses to replace an existing foreign target.

Mongo publishes no host port. The app/Mongo and app/tunnel networks are internal;
only the connector has egress. The database volume is dedicated to staging and
is never deleted by the release helper. Fixed root-owned policy accepts only
an immutable Identity image digest, source SHA and Vault ID, checks project
ownership including stopped containers and refuses foreign volumes/networks.
It neither stacks another Compose file nor modifies a product project.

The first operator installation remains explicit. The reviewed installer and
SSH entry point install only the fixed wrapper/policy and a sudo rule granting
`ocarun` that argument-validating staging wrapper. No shell, Docker command,
Docker-group membership or unrestricted sudo is granted. If a reviewed ephemeral Actions
bootstrap is used instead, first establish the actual existing host authority;
working OCI API credentials do not themselves grant root inside the VM. Never
abuse a Chronicles/Chess-only wrapper to install Identity.

`host/bootstrap-identity-staging-over-ssh.sh` resolves protected Infra main and
rechecks it on the adopted A1. It installs `/usr/local/sbin/shadowops-identity-staging`,
its private directories and the isolated policy. Operator-only deployment accepts:

```
sudo /usr/local/sbin/shadowops-identity-staging deploy sha256:<manifest-digest> <40-char-source-SHA> <Vault-OCID>
```

Before calling that command, independently verify the image's build provenance
against `identity-service.yml`, protected-main ancestry and the exact source SHA.
The manual Actions deploy first verifies the exact source checks, protected-main
ancestry, arm64 manifest and build attestation, then invokes only the installed
Identity wrapper through OCI Run Command. It logs only a sanitized
startup receipt; its local state explicitly says `public_login_verified=false`.
The Mongo bootstrap initializes only an empty replica through the localhost
exception; retries authenticate existing users and cannot reset live passwords.
An incorrect root or application password stops the deployment.

The disposable image/Mongo test proves actual TLS signup/login/token/freshness,
logout revocation, startup with the exact runtime role, wrong-password retry
rejection and account persistence after restarting Mongo. It uses an isolated
internal Docker network and publishes no port. Fixtures and all volumes are
removed afterwards; nothing is uploaded or copied into a real environment.

Before consumer activation, complete and record backup/restore (including
preventing restored sessions/credentials from reviving revoked access), certificate
rotation/expiry monitoring, deployment provenance, the reserved `shadowops:`
legacy-namespace preflight, actual Chronicles login/save/reload/logout and a
consumer rollback. Native flags remain off until those gates pass. Production,
legacy account linking, Chess and CKA are outside this first pilot activation.


## One-use authority receipt, 2026-10-30

The user requested an ephemeral Infra workflow using the existing Actions
secrets. [Run 41093882304](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41093882304)
successfully authenticated to OCI and returned only:

```
IDENTITY_STAGING_AUTHORITY docker=no identity_wrapper=no repo=yes operator_sudo=no
```

This verifies that the current agent can observe the A1 but cannot perform the
first Identity installation. No permission was granted or root command executed.
The credential-backed one-use workflow is retired by this handoff; the source
and output-validation tests remain for audit. A first authorized operator must
install the reviewed fixed wrapper/sudo rule before Actions can deploy Identity.
The existing `/opt/shadowops-infra` checkout is present. Never use another
product's wrapper or alter its scope to get around this missing installation.
