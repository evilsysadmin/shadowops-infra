# Star Adventures · candidate for a private ShadowOps ID staging release

The public static Pages publisher is deliberately **paused** with
`config/staradvs-protected-release.json = {"mode":"pending-identity"}`.
The old published aliases are not protected by that setting. The separate
[Access quarantine workflow](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-access-quarantine.yml)
remains the prerequisite to closing those aliases.

## What now runs on Infra main

[Star Adventures · protected ShadowOps ID bundle candidate (no deploy)](https://github.com/evilsysadmin/shadowops-infra/actions/workflows/staradvs-protected-candidate.yml)
builds a genuine runnable candidate from the **exact current, already-green**
`evilsysadmin/star-adventures/main` SHA. It:

1. Independently admits the game's source-main CI and checks that no
   Infra-owned staging policy changed since this job checked out.
2. Checks out the exact game commit, installs the lockfile, builds Vite and
   writes an immutable `release.json` with game SHA and compiled JS hash.
3. Adds the **exact Infra-owned** Pages advanced-mode `_worker.js`, which
   requires the dedicated `staradvs` audience, Ed25519 JWT verification,
   live Identity freshness/revocation and an app-only proof binding.
4. Re-verifies Worker bytes, manifest, entrypoint integrity and that
   the compiled repository HEAD still equals the admitted source SHA.
   The source-main/green CI admission happens in an **independent job**,
   before executing any game-source code. The compilation job does not
   receive a GitHub API token or Cloudflare credentials.
5. Uploads a **7-day** GitHub Actions artifact named
   `staradvs-protected-candidate-<source-sha>`. It contains a frontend
   build and public Worker code, **never** a credential or user token.

No Cloudflare access token, Pages API token, OCI credentials, production
secrets, staging environment approval or mutating command is available to
this workflow. An admitted source SHA can become superseded by a newer game
main during compilation; the artifact remains an explicitly pinned candidate
for that SHA, **not** proof that it matches the latest main at publication
time. The later protected publisher must recheck game and Infra head SHAs. PRs execute **offline tests only**, and do not build or
upload source code; only a trusted Infra main push or explicitly requested
main workflow dispatch creates a candidate.

## What this does NOT do

**A build artifact is not a deployed game.** In particular it does not
install a Worker, modify DNS, bind a secret, provision the Identity
audience, protect old Pages aliases, check an authenticated live browser
journey or unpause the public publisher.

After quarantine, the staging operator must:

- Provision `staradvs` via the existing isolated Identity
  `action=provision`, `staradvs_consumer=enable`, followed by the
  **appropriate reviewed deployment of the actual running staging IdP**
  (an OCI Vault bundle alone does not update a live container).
- Use the protected private Pages policy and isolated proof binding actions.
- Review and execute a distinct protected-Worker release that replaces
  the old public-200 verifier with actual anonymous-denial and authenticated
  browser E2E, checking old aliases too.
- Only mark it deployed when the real origin serves the pinned game SHA
  behind ShadowOps ID and logout/revocation blocks further asset access.

Do not confuse a green candidate or a successful `npm run build` with a
green live deployment.
