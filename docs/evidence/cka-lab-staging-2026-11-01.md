# CKA staging lab publication — 2026-11-01

The restricted staging POC is published at
https://staging.cka.shadowops.dpdns.org using the existing A1's bounded rootless
Compose runtime and private Kubernetes cluster. This is a deployment receipt,
not a claim that a real candidate has completed and graded a laboratory.

## Exact release

- Infra protected main: `15fd93bd0655c9710f3d06ecb5fe45393cc5cb27` ([#393](https://github.com/evilsysadmin/shadowops-infra/pull/393)).
- CKA source: `6a6585abeda9034435ae82e14a04ee184dd7ba71`.
- Admitted multiarch image: `sha256:d8477ac4081e1573976f57f2d961eee9033d25a39b94c3231d6afbb66257271b`.
- [Publication run 41356472290](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41356472290): all three jobs succeeded.

## Verified live

The operator successfully ran `make cka-lab-tunnel-start` followed by the
read-only `make cka-lab-tunnel-verify` on the A1. Both returned the exact source
and digest, `public_endpoint_enabled=true` and `anonymous_denied=true`.
The private API had already verified `authenticated_staging_configured=true`.

Independent HTTPS checks at approximately 22:30–22:32 UTC verified:

- Browser `/release.json`: application `cka-exam-simulator`, exact CKA source,
  mode `restricted-lab-staging`.
- API `/api/labs/release`: the same application/source, mode `restricted-lab-pilot`.
- API `/readyz`: HTTP 200 and `{"status":"ok"}`.
- Anonymous POST `/api/labs/capabilities`: HTTP 401, exact staging browser CORS
  origin, `Cache-Control: no-store`, no session cookie.
- Browser HTML: `CKA // LAB`, local JavaScript asset, `no-store`, and CSP allowing
  the fixed staging Identity and lab API origins.

The fresh provisioning receipt counted 13 Vault secrets and 6 tunnels both
before and after the retry, inside the checked free envelopes of 150 and 1,000.
It created no compute, Vault or master key. The retry reused the existing lab
custody and tunnel. No additional VM, host resize or OCI storage allocation was made.

## Integration proof and its boundary

[CI run 41355739074](https://github.com/evilsysadmin/shadowops-infra/actions/runs/41355739074)
passed the exact published controller with a real disposable rootless Compose /
Kind cluster: three curated exercises, two authenticated synthetic identities,
unexpired revocation, candidate egress denial and durable restart cleanup.
A populated synthetic tunnel env file reproduced the installed Compose resolved
export. The sole exported credential was checked privately against the expected
token, and its delivery to the created vendor container was verified. That
container was never started and no live Cloudflare token was used in CI.

These synthetic tests do not establish positive real-Identity candidate acceptance
on the A1. The deployment receipts intentionally retain
`candidate_acceptance_verified=false`.

## Real-user browser evidence

After publication the operator reported that the authenticated staging laboratory
works and supplied a browser capture. It shows a prepared curated exercise and
`kubectl get po` returning two ready, Running application pods through the lab
terminal. This establishes positive real-user preparation and command execution
on the deployed POC. User, session and namespace identifiers are not retained in
this receipt.

A passing repair/grade and confirmed finish/slot reuse were not shown in that
capture and remain pending. The immutable deployment artifact still correctly
records `candidate_acceptance_verified=false`; it does not update when a user
performs a laboratory.

## Remaining real-user acceptance

With an actual staging Identity session in the published browser:

1. Prepare a curated laboratory and receive its terminal.
2. Execute a command, repair the stated problem and check the result against
   actual Kubernetes state.
3. Finish the attempt and confirm the slot becomes available again.
4. Verify logout denies further operations; a second user cannot operate the
   first user's attempt. There is one global slot, so another user sees occupied
   while the lease is active.

Record an observed result before declaring that journey accepted. Keep user
passwords, access tokens, session IDs and private exercise fixtures out of
receipts. The operational commands and boundaries are documented in
[the staging runbook](../cka-lab-staging.md).
