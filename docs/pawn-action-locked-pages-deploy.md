# Pawn Action · first locked Pages deployment (manual-only)

This is a separate, operator-approved deployment of ONLY the existing
deny-all Worker holding shell. It is not Pawn Action gameplay, an Identity
consumer activation, a game R2 upload, or a custom-domain/DNS change.

The previously reviewed \`pawn_action_pages_shell.py\` generator builds exactly:
\`_worker.js\` (deny-all except locked status on canonical host),
\`index.html\` (no game links, safe static fallback) and \`_headers\`
(restrictive noncacheable defaults). It rejects extra files or modifications.

1. First reserve the dedicated empty Direct Upload project using the existing
   manually guarded \`pawn-action-pages-create.yml\`. The create-once script
   must prove that the Pages project has **no** preview/production deployments,
   custom domain or staging DNS. Existing content must never be overwritten.
2. Dispatch \`Pawn Action · deploy locked Pages holding shell (manual only)\`
   on protected Infra \`main\` with \`operation=deploy-locked\` and exactly
   \`confirm=pawn-action-staging:locked\`. The default \`plan\` does not deploy.
3. The protected staging environment must contain distinct
   \`CLOUDFLARE_API_TOKEN\` (read-only zone/Pages/DNS/deployment inventory)
   and \`PAWN_ACTION_PAGES_DEPLOY_TOKEN\` (Pages deployment only) plus the
   exact \`CLOUDFLARE_ACCOUNT_ID\`. Never reuse production deployment tokens.
   The workflow checks Infra HEAD and performs a **fresh empty-project
   preflight before any Pages deployment**. On an uncertain result, stop
   and inspect manually: no retries or rollback/deletion are automatic.
4. After the one deployment, read back the Pages project/deployments inventory
   and require that anonymous GET and HEAD for every path in the
   canonical locked-host deny list, plus the status endpoint, return 404
   on the exact Cloudflare-assigned Pages alias. The alias is validated
   against the strict pawn-action-staging[-suffix].pages.dev pattern,
   NOT by permissive prefix matching. Any asset exposed on GET while
   HEAD is denied still fails the external verification. If Wrangler silently uploaded only the HTML
   fallback, the public root would return 200 and verification must fail.

**This does not attach the canonical staging DNS.** The canonical locked
surface probe remains a separate future gate after custom-domain attachment.
No gameplay, credentials, release pointer, source-main or R2 is published,
and Chess Studio's legacy game stays untouched.

PR/push jobs test contract logic offline only; the Cloudflare deployment is
available solely through explicit \`workflow_dispatch\` under the staging
environment. Successful offline tests never imply any live Pages resource.
