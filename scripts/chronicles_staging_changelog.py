#!/usr/bin/env python3
"""Read-only, best-effort changelog for a VERIFIED Chronicles staging Pages release.

The release workflow calls this only after exact-SHA API, HTTPS and browser
checks. This module does not authorize publication or create release receipts.
"""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

INFRA = "evilsysadmin/shadowops-infra"
SOURCE = "evilsysadmin/chronicles-of-matthias"
PAGES_WORKFLOW = ".github/workflows/chronicles-pages-release.yml"
RECEIPT = re.compile(r"chronicles-pages-staging-([0-9a-f]{40})\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_ARTIFACT_PAGES = 8
MAX_COMMITS = 60


class ChangelogError(RuntimeError):
    """GitHub evidence is missing or inconclusive; NOT a deployment failure."""


def github_get(path: str, token: str) -> dict:
    if not token:
        raise ChangelogError("GitHub read token unavailable")
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ChangelogError("GitHub read failed") from exc
    if isinstance(result, list):
        return {"_items": result}
    if not isinstance(result, dict):
        raise ChangelogError("Malformed GitHub response")
    return result


def trusted_receipt(artifact: dict, run: dict) -> bool:
    """A named artifact alone cannot prove a successful staging release."""
    if not isinstance(artifact, dict) or artifact.get("expired") is not False:
        return False
    origin = artifact.get("workflow_run")
    if not isinstance(origin, dict):
        return False
    run_id = origin.get("id")
    return (
        isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0
        and origin.get("head_branch") == "main"
        and isinstance(run, dict) and run.get("id") == run_id
        and run.get("status") == "completed" and run.get("conclusion") == "success"
        and run.get("path") == PAGES_WORKFLOW and run.get("head_branch") == "main"
        and (run.get("repository") or {}).get("full_name") == INFRA
        and run.get("event") in {"push", "schedule", "workflow_dispatch"}
    )


def last_verified_sha(current: str, get) -> str | None:
    """Read newest trusted Pages receipt, including the current SHA if repeated.

    Old receipts can expire; no baseline is preferable to inventing one.
    """
    for page in range(1, MAX_ARTIFACT_PAGES + 1):
        listing = get(f"repos/{INFRA}/actions/artifacts?per_page=100&page={page}")
        artifacts = listing.get("artifacts")
        if not isinstance(artifacts, list):
            raise ChangelogError("Malformed artifact listing")
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            match = RECEIPT.fullmatch(str(item.get("name", "")))
            if not match or item.get("expired") is not False:
                continue
            run_id = (item.get("workflow_run") or {}).get("id")
            if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
                continue
            run = get(f"repos/{INFRA}/actions/runs/{run_id}")
            if trusted_receipt(item, run):
                return match.group(1)
        if len(artifacts) < 100:
            return None
    return None


def short_text(value: object, length: int = 150) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:length]


def changes_for(current: str, get) -> dict:
    if not SHA.fullmatch(current):
        raise ValueError("Invalid source SHA")
    result = {
        "schema": 1,
        "source_sha": current,
        "previous_sha": None,
        "status": "no_baseline",
        "compare_url": None,
        "total_commits": None,
        "commits": [],
        "pull_requests": [],
        "truncated": False,
    }
    previous = last_verified_sha(current, get)
    result["previous_sha"] = previous
    if previous is None:
        return result
    if previous == current:
        result["status"] = "already_verified"
        result["total_commits"] = 0
        return result

    result["compare_url"] = f"https://github.com/{SOURCE}/compare/{previous}...{current}"
    diff = get(f"repos/{SOURCE}/compare/{previous}...{current}?per_page=100&page=1")
    if diff.get("status") not in {"ahead", "identical"}:
        result["status"] = "non_linear"
        return result
    commits = diff.get("commits")
    total = diff.get("total_commits")
    if not isinstance(commits, list) or not isinstance(total, int) or total < 0:
        raise ChangelogError("Malformed commit comparison")
    result["total_commits"] = total
    result["truncated"] = total > MAX_COMMITS
    result["status"] = "partial" if result["truncated"] else "changes"

    seen = set()
    for commit in commits[:MAX_COMMITS]:
        commit_sha = commit.get("sha") if isinstance(commit, dict) else None
        if not isinstance(commit_sha, str) or not SHA.fullmatch(commit_sha):
            raise ChangelogError("Malformed compared commit SHA")
        message = short_text((commit.get("commit") or {}).get("message", "").split("\n")[0])
        result["commits"].append({"sha": commit_sha, "message": message})
        try:
            associated = get(f"repos/{SOURCE}/commits/{commit_sha}/pulls?per_page=100")
            prs = associated.get("_items")  # populated by the GET adapter for list responses
            if not isinstance(prs, list):
                raise ChangelogError("Malformed associated PR response")
            for pr in prs:
                if not isinstance(pr, dict) or not pr.get("merged_at"):
                    continue
                num = pr.get("number")
                if not isinstance(num, int) or num <= 0 or num in seen:
                    continue
                if ((pr.get("base") or {}).get("repo") or {}).get("full_name") != SOURCE:
                    continue
                seen.add(num)
                result["pull_requests"].append({
                    "number": num,
                    "title": short_text(pr.get("title")),
                    "url": f"https://github.com/{SOURCE}/pull/{num}",
                })
        except ChangelogError:
            result["status"] = "partial"
            result["truncated"] = True
    return result


def _markdown_cell(value: object) -> str:
    """Escape untrusted PR titles before showing them in a Markdown table."""
    value = short_text(value)
    return (html.escape(value, quote=False)
            .replace("\\", "\\\\").replace("|", "&#124;")
            .replace("[", "&#91;").replace("]", "&#93;"))


def render_summary(data: dict) -> str:
    """One readable report shared by the Actions summary and downloadable MD."""
    current = data["source_sha"]
    previous = data["previous_sha"]
    status = data["status"]
    report_url = "https://github.com/" + INFRA + "/actions/runs/" + os.environ.get("GITHUB_RUN_ID", "")
    lines = [
        "# 🚀 Chronicles · staging",
        "",
        "✅ **Versión pública verificada** · API, HTTPS y pruebas de navegador superadas.",
        "",
        "| | |",
        "|:--|:--|",
        f"| **Versión** | [{current[:12]}](https://github.com/{SOURCE}/commit/{current}) |",
        (f"| **Anterior** | [{previous[:12]}](https://github.com/{SOURCE}/commit/{previous}) |"
         if previous else "| **Anterior** | No hay evidencia retenida |"),
        f"| **PR identificadas** | {len(data['pull_requests'])} |",
        f"| **Commits** | {data['total_commits'] if data['total_commits'] is not None else 'Sin dato'} |",
        "",
        "[🎮 Abrir staging](https://staging.chronicles.shadowops.dpdns.org)"
    ]
    if data.get("compare_url"):
        lines[-1] += f" · [🔎 Comparar con la versión anterior]({data['compare_url']})"
    lines.extend(["", "## Qué ha cambiado", ""])
    if status == "already_verified":
        lines.append("Reverificación del mismo SHA: **no hay cambios nuevos**.")
    elif status == "no_baseline":
        lines.append("Sin baseline verificable en los artefactos retenidos; no se inventa un diff.")
    elif status == "non_linear":
        lines.append("Los SHA no siguen una progresión lineal. Revisar rollback/divergencia manualmente.")
    elif status == "unavailable":
        lines.append("Changelog no disponible; el resultado del despliegue no depende de esta consulta.")
    else:
        if data["pull_requests"]:
            lines.extend(["| PR | Cambio |", "|:--|:--|"])
            for pr in data["pull_requests"]:
                lines.append(
                    f"| [#{pr['number']}]({pr['url']}) | {_markdown_cell(pr['title'])} |"
                )
        else:
            lines.append("No se identificaron PR asociadas; los commits están enlazados debajo.")
        if data["truncated"]:
            lines.extend(["", "⚠️ **Historial parcial:** hay más commits o falló alguna consulta de PR."])
        if data["commits"]:
            lines.extend(["", "<details><summary>Ver commits incluidos</summary>", ""])
            for commit in data["commits"]:
                lines.append(
                    f"- [{commit['sha'][:12]}](https://github.com/{SOURCE}/commit/{commit['sha']})"
                    f" — {_markdown_cell(commit['message'])}"
                )
            lines.extend(["", "</details>"])
    lines.extend([
        "", "### Informe descargable",
        "",
        "En **Artifacts** de esta ejecución: **chronicles-staging-release-notes-<SHA>**.",
        "Incluye un **reporte HTML** que se abre en el navegador y una copia **RELEASE_NOTES.md**.",
        "",
        "> Este resumen es informativo. La evidencia firmada/validada de despliegue "
        "sigue siendo el recibo exact-SHA de API y Pages."
    ])
    return "\n".join(lines) + "\n"


def render_html(data: dict) -> str:
    """Self-contained, offline HTML for the release artifact; no scripts/assets."""
    esc = lambda value: html.escape(str(value), quote=True)
    current = data["source_sha"]
    previous = data["previous_sha"]
    status = data["status"]
    label = {
        "already_verified": "Misma versión, reverificada",
        "no_baseline": "Sin versión anterior verificable",
        "non_linear": "Historial no lineal",
        "unavailable": "Detalle de cambios no disponible",
        "partial": "Listado parcial",
        "changes": "Cambios identificados",
    }.get(status, "Estado desconocido")
    old = (f'<a href="https://github.com/{SOURCE}/commit/{previous}">{esc(previous[:12])}</a>'
           if previous else "Sin dato")
    target = f'https://github.com/{SOURCE}/commit/{current}'
    compare = (f'<a class="button secondary" href="{esc(data["compare_url"])}">Comparar versiones ↗</a>'
               if data.get("compare_url") else "")
    if data["pull_requests"]:
        items = "".join(
            '<li><a href="' + esc(pr["url"]) + '">#' + esc(pr["number"]) +
            '</a><span>' + esc(pr["title"]) + '</span></li>'
            for pr in data["pull_requests"]
        )
        changes = '<ul class="prs">' + items + '</ul>'
    elif status == "already_verified":
        changes = '<p>Sin cambios nuevos: solo se ha reverificado la versión existente.</p>'
    elif status == "no_baseline":
        changes = '<p>No hay una versión anterior verificable entre los recibos retenidos.</p>'
    elif status == "non_linear":
        changes = '<p>La comparación no es lineal. Es necesario revisar posible rollback o divergencia.</p>'
    elif status == "unavailable":
        changes = '<p>GitHub no ha podido facilitar el historial; el despliegue no depende de este informe.</p>'
    else:
        changes = '<p>No se identificaron PR fusionadas asociadas a los commits mostrados.</p>'
    if data["truncated"]:
        changes += '<p class="warning">⚠ Listado parcial: límite de commits o consulta de PR incompleta.</p>'
    commits = "".join(
        '<li><a href="https://github.com/' + SOURCE + '/commit/' + esc(commit["sha"]) +
        '">' + esc(commit["sha"][:12]) + '</a><span>' + esc(commit["message"]) + '</span></li>'
        for commit in data["commits"]
    )
    details = ('<details><summary>Ver commits (' + esc(len(data["commits"])) +
               ')</summary><ul class="prs">' + commits + '</ul></details>') if commits else ""
    count = data["total_commits"] if data["total_commits"] is not None else "—"
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Chronicles · Staging · {esc(current[:12])}</title>
<style>
:root{{color-scheme:dark;font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}
*{{box-sizing:border-box}}
body{{margin:0;background:#101722;color:#eaf0f7}}
main{{max-width:980px;margin:0 auto;padding:42px 24px 80px}}
header{{padding:40px;border-radius:22px;background:linear-gradient(125deg,#243954,#182638 75%);border:1px solid #3b5069}}
.eyebrow{{color:#bdd4ed;text-transform:uppercase;letter-spacing:.13em;font-size:.78rem;font-weight:700}}
h1{{font-size:clamp(2rem,5vw,3rem);letter-spacing:-.045em;margin:12px 0}}
h2{{font-size:1.35rem;margin:34px 0 12px}}
.pill{{display:inline-block;border:1px solid #4c806d;background:#1d4336;color:#bdf2d7;border-radius:100px;padding:5px 12px;font-size:.84rem}}
.subtle{{color:#b3c2d2}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:22px 0}}
.metric{{background:#1b2635;border:1px solid #314154;border-radius:14px;padding:17px}}
.metric small{{display:block;color:#a8b9cc;margin-bottom:8px}}
.metric strong{{font-size:1.15rem}}
a{{color:#a7d3ff;text-decoration:none}}
a:hover{{text-decoration:underline}}
.actions{{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}}
.button{{display:inline-block;background:#dbeeff;color:#10263e;padding:10px 16px;border-radius:9px;font-weight:650}}
.button.secondary{{background:#25384d;color:#d4e8fe;border:1px solid #465e78}}
section{{background:#192432;border:1px solid #314154;border-radius:16px;padding:22px;margin-top:22px}}
.prs{{list-style:none;margin:16px 0 0;padding:0}}
.prs li{{padding:12px 0;display:flex;gap:16px;border-bottom:1px solid #344257;overflow-wrap:anywhere}}
.prs li:last-child{{border-bottom:0}}
.prs li a{{font-weight:750;flex-shrink:0}}
details{{margin-top:24px}}
summary{{cursor:pointer;color:#afceef}}
.warning{{color:#ffd59b}}
footer{{font-size:.86rem;color:#9aabbf;margin-top:30px}}
</style></head>
<body><main><header>
<div class="eyebrow">ShadowOps / Chronicles</div>
<h1>Staging · Release notes</h1>
<span class="pill">✓ Versión pública verificada</span>
<p class="subtle">API, HTTPS y navegador verificados por el workflow. Estado del changelog: {esc(label)}.</p>
<div class="actions"><a class="button" href="https://staging.chronicles.shadowops.dpdns.org">Abrir staging ↗</a>{compare}</div>
</header>
<div class="metrics">
<div class="metric"><small>Versión verificada</small><strong><a href="{esc(target)}">{esc(current[:12])}</a></strong></div>
<div class="metric"><small>Anterior verificada</small><strong>{old}</strong></div>
<div class="metric"><small>PR identificadas</small><strong>{len(data["pull_requests"])}</strong></div>
<div class="metric"><small>Commits</small><strong>{esc(count)}</strong></div>
</div>
<section><h2>Qué ha cambiado</h2>{changes}{details}</section>
<footer>Informe de lectura. Los recibos exact-SHA de API/Pages son la fuente de verdad del despliegue.</footer>
</main></body></html>
"""

def main() -> int:
    if len(sys.argv) != 2 or not SHA.fullmatch(sys.argv[1]):
        print("Expected exact Chronicles source SHA", file=sys.stderr)
        return 64
    current = sys.argv[1]
    try:
        data = changes_for(current, lambda path: github_get(path, os.environ.get("GH_TOKEN", "")))
    except (ChangelogError, ValueError, TypeError, KeyError):
        data = {
            "schema": 1, "source_sha": current, "previous_sha": None,
            "status": "unavailable", "compare_url": None,
            "total_commits": None, "commits": [], "pull_requests": [],
            "truncated": False,
        }
    output = Path("verified-pages/changes.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    (output.parent / "RELEASE_NOTES.md").write_text(render_summary(data), encoding="utf-8")
    (output.parent / "release-notes.html").write_text(render_html(data), encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(render_summary(data))
    print(f"CHRONICLES_STAGING_CHANGELOG status={data['status']} sha={current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
