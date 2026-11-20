# Star Adventures staging ShadowOps ID — read-only cutover inventory

The old public static publisher is paused by the protected-release source
policy. This inspection provides **current evidence**, but neither enables
the audience nor uploads a Cloudflare Pages Worker.

Run the offline contracts:

    python3 -m unittest discover -s tests -p test_staradvs_identity_readiness.py -v

From the protected Infra staging environment, the optional GET-only check is:

    python3 scripts/staradvs_identity_readiness.py inspect

It observes only the exact already-owned Pages project, custom domain and
Cloudflare DNS record, the production/preview fail-closed configuration flags,
whether the *name and type* of the Star Adventures app-only secret binding
are present, and the actual Pages aliases disclosed by Cloudflare. The
credential **value is never logged, exported or read**. Unexpected project
identity, source/branch or alias hostname blocks inspection.

A public HTTPS GET to the isolated staging Identity login with
app=staradvs checks that the target is explicitly recognized; a 200
from some other page is insufficient. Guest GET/HEAD probes then require 401
from the canonical root, index, bridge and release resources and 404 from
the main Pages alias and discovered current/immutable aliases. Redirects are
not followed, TLS verification is required, and no cookies or tokens are
provided.

The workflow runs offline tests on PRs and performs a sanitized live probe
only on trusted main via manual dispatch or its daily schedule. It reports
**PENDING** while any requirement is absent. A successfully completed
inventory job does not imply a playable or protected release.

Even if the inventory reaches next_gate_ready=true, its can_activate
remains false: a real signed-in session journey and revocation test, session
renewal, identity failure behavior, full historical alias review and a
rollback/forward plan still have to pass. There is no mutating deployment
step here.

**Historic static Pages deployments may remain accessible.** The read-only
probe covers current project aliases found via project metadata, not all
historic deployment IDs. Older aliases require a separately scoped
Cloudflare deployment inventory and an enforceable quarantine before
claiming universal protection.
