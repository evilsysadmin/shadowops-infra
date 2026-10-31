# CKA shared account staging handoff

CKA source/API and browser belong to `evilsysadmin/cka-exam-simulator`; Infra
owns this deployment. The application source is merged in CKA #29 (isolated
account API) and #30 (staging browser). No laboratory runtime is deployed.

## One operator installation, before activation

The currently installed A1 policy can operate Identity and Chronicles, but has
no CKA account command and accepts only the original consumer bundle. An agent
must not use their wrappers, an arbitrary OCI shell or Docker permissions to
install a new root policy. From the existing clean root-owned Infra checkout:

```
cd /opt/shadowops-infra
sudo git fetch origin main
sha="$(sudo git rev-parse origin/main)"
sudo git checkout --detach "$sha"
sudo bash host/install-cka-account-staging.sh "$sha"
```

Expected final marker: `CKA_ACCOUNT_STAGING_OPERATOR_INSTALLED`. This verifies
root ownership, exact clean source and policy hashes; updates the known consumer
schema; installs only the fixed account deployer/inspection command and separate
Compose policy. It neither registers CKA, changes secrets, starts containers nor
enables labs. Existing Identity keys, accounts, sessions and Chronicles proof
remain intact. The agent gets no general shell, Docker, install or restore sudo.

## Actions-owned activation

Use `cka-account-staging.yml` from protected Infra main, environment staging.
Its contracts run on PR/main with no provider credentials. Operational actions
are deliberate manual dispatches; merges alone perform no cloud mutation.

A read-only `admit` action verifies source CI, both image architectures and
exact-source attestation without OCI/Cloudflare credentials or mutations.

1. `inspect` verifies the installed fixed account policy. Identity provisioning
   itself repeats this capability gate before enabling CKA or changing custody.
2. Run `identity-staging-operations.yml`, action `backup`; require success.
3. CKA action `provision` explicitly adds a new independent `cka-simulator` SOC
   to the existing Identity bundle once. All preexisting fields are preserved;
   repeated activation keeps the same proof. It creates only the CKA account
   tunnel/DNS and `cka-account-staging-runtime` Vault secret, copying only the
   CKA proof, public Identity TLS CA and separately retrieved public JWKS. Never copy signing, Mongo,
   backup, Chronicles or scenario-generation credentials into CKA.
4. Deploy the already admitted Identity service image through its existing
   owner workflow, using the reviewed published Identity source SHA. Its new
   private configuration enables CKA's already pinned origin/return target.
   Check actual readiness, source and `/login?app=cka-simulator` before proceeding.
5. CKA action `deploy` admits current source main only after the exact three
   source workflows succeed, verifies the account image attestation/source ref
   and digest plus both architectures, then invokes the fixed root helper.
   Root policy requires a recent authenticated backup receipt, no container
   collisions, fixed read-only/nonroot Compose policy and narrow secret mount.
   It publishes no host port, Docker socket, lab credentials or shared volume.
   The account container joins two internal networks, including the Identity
   origin network, and uses private-CA TLS on port 9443 with the fixed SNI/Host.
   It has no general egress/default route to cloud instance metadata.
   Mandatory public HTTPS verification follows even if OCI omits command text:
   exact release SHA/mode, readiness, anonymous account 401 and privileged 404s.
6. CKA action `pages` repeats source/image admission and actual exact-source API
   verification, builds only `dist-account-staging`, and publishes the separate
   `cka-account-staging` Pages project/domain. Source and Infra owner are checked
   again before mutation. Foreign DNS/project targets are never overwritten.
7. Actual browser acceptance must reuse an existing central account/cookie from
   Chronicles without CKA registration, verify the same UUID, no browser tokens
   in storage/URLs, protected cookie, logout rejection of unexpired JWTs in both
   consumers, and desktop/mobile captures. Candidate fixture screenshots alone
   do not complete public SSO acceptance.

Frontend: `https://staging.cka.shadowops.dpdns.org`.
Account API: `https://cka-api-staging.shadowops.dpdns.org`.
Identity: `https://id-staging.shadowops.dpdns.org`.
The original `https://cka.shadowops.dpdns.org` remains a separate static preview.

The API is account-only, with a stable central UUID and no product database,
password, lab grant, terminal, Kubernetes client, factory or lease controller.
Live freshness checks are never cached, and credentials are never sent to Vite.
The native account image has bounded per-user/global checks and concurrency.
Readiness verifies process/configuration; actual user freshness needs the live
acceptance above. Infrastructure source/HTTPS receipts do not replace it.

Rollback: keep the independent Pages site unpublished until API acceptance;
if an activated pilot must be stopped, dispatch action `disable`. It stops
only the verified CKA account containers and removes only the exact owned
account Pages custom-domain/DNS bindings, retaining the Pages project and all
central custody. Unknown containers or foreign DNS block that operation. Never roll back by restoring an older entire
Identity bundle: that could remove/replace unrelated custody. Preserve central
accounts, UUIDs, backups and the existing Chronicles consumer. Off-host disaster
recovery and isolated per-user runners remain prerequisites for production/labs.
