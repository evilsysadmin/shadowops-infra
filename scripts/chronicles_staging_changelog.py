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


def render_summary(data: dict) -> str:
    lines = ["### Chronicles staging · cambios de esta release", ""]
    current = data["source_sha"]
    lines.append(f"**Versión verificada:** [{current[:12]}](https://github.com/{SOURCE}/commit/{current})")
    previous = data["previous_sha"]
    if previous:
        lines.append(f"**Anterior verificada:** [{previous[:12]}](https://github.com/{SOURCE}/commit/{previous})")
    status = data["status"]
    if status == "already_verified":
        lines.append("\nReverificación del mismo SHA: **no hay cambios nuevos**.")
    elif status == "no_baseline":
        lines.append("\nSin baseline verificable en los artefactos retenidos; no se inventa un diff.")
    elif status == "non_linear":
        lines.append("\nLos SHA no siguen una progresión lineal. Revisar rollback/divergencia manualmente.")
    elif status == "unavailable":
        lines.append("\nChangelog no disponible; el resultado del despliegue no depende de esta consulta.")
    else:
        lines.append(f"\n**Commits detectados:** {data['total_commits']}")
        if data["pull_requests"]:
            lines.extend(["", "**PR incluidas:**"])
            for pr in data["pull_requests"]:
                title = html.escape(pr["title"], quote=False)
                lines.append(f"- [#{pr['number']}]({pr['url']}) — {title}")
        if not data["pull_requests"]:
            lines.append("\nSin PR asociadas identificadas; consulta los commits en el diff.")
        if data["truncated"]:
            lines.append("\n**Listado parcial:** límite de commits o consulta de PR incompleta.")
    if data.get("compare_url"):
        lines.append(f"\n[Comparar versiones]({data['compare_url']})")
    lines.append("\nLa release solo se certifica mediante las comprobaciones y recibos del pipeline.")
    return "\n".join(lines) + "\n"


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
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(render_summary(data))
    print(f"CHRONICLES_STAGING_CHANGELOG status={data['status']} sha={current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
