# Portal release admission after unrelated Infra merges

A long Blender build can overlap with security fixes to Chronicles. A blanket `GITHUB_SHA == main` gate incorrectly rejected the portal release even when its source and workflow were unchanged.

The release gate now accepts only an exact original SHA or a **direct ancestor** of main with **at most 100 intervening commits** and a fully inspectable diff of fewer than 300 changed files. Changes to `portal/**`, `scripts/portal_*`, `tests/test_portal_*`, or the portal Pages/CI workflows cause the release to fail closed. File renames, divergent ancestry, missing evidence and GitHub errors also block.

The same admission runs before staging build and every staging/production Cloudflare mutation. Other requirements remain unchanged: exact staging artifact, public TLS + hash verification, isolated Pages projects and no foreign DNS overwrite. No games or tunnels are affected.
