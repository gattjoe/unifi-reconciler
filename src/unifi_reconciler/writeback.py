"""Write-back of real UDM policy IDs after a v2 create.

After the reconciler creates a new rule on the controller, the controller assigns
a real ``_id``. That id must be committed back to the repo (managed-state.json +
the policy YAML) so subsequent reconcile runs UPDATE rather than re-CREATE.

Two modes:
  - **Local** (no GitHub token): updates the files on disk. The caller commits.
  - **PR** (GitHub token + repo configured): opens a pull request via the GitHub
    API updating the same files. The PR is the review gate before the merge closes
    the loop.

The GitHub API calls use only the stdlib ``urllib.request`` — no extra deps.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_WRITEBACK_TITLE = "chore(unifi-reconciler): write back real UDM ids for newly created rules"
_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class WritebackError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Shared content builders
# --------------------------------------------------------------------------- #

def _validate_id(real_id: str, name: str) -> None:
    """Raise WritebackError if real_id contains characters unsafe for YAML or regex."""
    if not _POLICY_ID_RE.match(real_id):
        raise WritebackError(
            f"controller returned unsafe policy id for {name!r}: {real_id!r} — "
            "expected alphanumeric/hyphen/underscore only"
        )


def _updated_state_json(state_path: Path, created_ids: dict[str, str]) -> str:
    """Return the new managed-state.json content with placeholder IDs replaced."""
    data = json.loads(state_path.read_text())
    new_managed = []
    for entry in data.get("managed", []):
        name = entry.get("name", "")
        new_managed.append({"name": name, "id": created_ids.get(name, entry.get("id", ""))})
    data["managed"] = new_managed
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _patch_yaml_id(content: str, real_id: str) -> str:
    """Replace or insert metadata.id in a policy YAML, preserving all other formatting."""
    patched, n = re.subn(
        r'^(  id:\s*)\S+',
        lambda m: m.group(1) + real_id,  # lambda avoids regex backreference expansion
        content,
        count=1,
        flags=re.MULTILINE,
    )
    if n:
        return patched
    # No existing id line — insert after the name: line under metadata:
    return re.sub(
        r'(metadata:\n  name:[^\n]+\n)',
        lambda m: f"{m.group(0)}  id: {real_id}\n",
        content,
        count=1,
    )


# --------------------------------------------------------------------------- #
# Local write-back
# --------------------------------------------------------------------------- #

def write_locally(
    rules_dir: Path,
    created_ids: dict[str, str],
    name_to_file: dict[str, Path],
) -> list[Path]:
    """Update managed-state.json and policy YAMLs in place. Returns modified paths."""
    changed: list[Path] = []

    for name, real_id in created_ids.items():
        _validate_id(real_id, name)

    state_path = rules_dir / "managed-state.json"
    if state_path.exists():
        new_content = _updated_state_json(state_path, created_ids)
        if new_content != state_path.read_text():
            state_path.write_text(new_content)
            changed.append(state_path)

    for name, real_id in created_ids.items():
        yaml_path = name_to_file.get(name)
        if yaml_path and yaml_path.exists():
            original = yaml_path.read_text()
            patched = _patch_yaml_id(original, real_id)
            if patched != original:
                yaml_path.write_text(patched)
                changed.append(yaml_path)

    return changed


# --------------------------------------------------------------------------- #
# GitHub API write-back
# --------------------------------------------------------------------------- #

def _gh(token: str, method: str, path: str, body: dict | None = None) -> Any:
    url = f"https://api.github.com/{path.lstrip('/')}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "unifi-reconciler/reconciler",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        snippet = exc.read().decode(errors="replace")[:200]
        raise WritebackError(
            f"GitHub API {method} {path}: HTTP {exc.code} — {snippet}"
        ) from exc
    except OSError as exc:
        raise WritebackError(f"GitHub API {method} {path}: {exc}") from exc


def _gh_file_sha(token: str, repo: str, path: str, ref: str) -> str:
    """Return the blob SHA of a file on a given ref, or '' if the file does not exist."""
    try:
        data = _gh(token, "GET", f"repos/{repo}/contents/{path}?ref={ref}")
        return data.get("sha", "")
    except WritebackError as exc:
        if "HTTP 404" in str(exc):
            return ""
        raise


def _gh_put_file(
    token: str, repo: str, path: str, content: str, branch: str, message: str
) -> None:
    sha = _gh_file_sha(token, repo, path, branch)
    body: dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch,
    }
    if sha:
        body["sha"] = sha
    _gh(token, "PUT", f"repos/{repo}/contents/{path}", body)


def _find_open_writeback_pr(token: str, repo: str) -> str | None:
    """Return the URL of an existing open write-back PR, or None."""
    try:
        prs = _gh(token, "GET", f"repos/{repo}/pulls?state=open&per_page=20")
    except WritebackError:
        return None
    for pr in (prs if isinstance(prs, list) else []):
        if str(pr.get("title", "")) == _WRITEBACK_TITLE:
            return str(pr["html_url"])
    return None


def open_github_pr(
    *,
    token: str,
    repo: str,
    rules_dir: Path,
    rules_repo_path: str,
    base_branch: str,
    created_ids: dict[str, str],
    name_to_file: dict[str, Path],
) -> str:
    """Open a PR on ``repo`` that writes back the real UDM ids. Returns the PR URL.

    If an open write-back PR already exists the caller gets its URL back without
    a new branch or PR being created — the operator must merge it first.
    """
    # Reject path traversal in the configured rules path before it reaches the API.
    for part in Path(rules_repo_path).parts:
        if part in ("..", "."):
            raise WritebackError(
                f"github_rules_path {rules_repo_path!r} contains unsafe component {part!r}"
            )

    for name, real_id in created_ids.items():
        _validate_id(real_id, name)

    existing = _find_open_writeback_pr(token, repo)
    if existing:
        return existing

    branch = f"unifi-reconciler/state-writeback-{int(time.time())}"

    # Create branch from base_branch HEAD.
    base_sha = _gh(token, "GET", f"repos/{repo}/git/ref/heads/{base_branch}")["object"]["sha"]
    _gh(token, "POST", f"repos/{repo}/git/refs", {
        "ref": f"refs/heads/{branch}",
        "sha": base_sha,
    })

    # Update managed-state.json
    state_path = rules_dir / "managed-state.json"
    if state_path.exists():
        new_state = _updated_state_json(state_path, created_ids)
        _gh_put_file(
            token, repo,
            f"{rules_repo_path}/managed-state.json",
            new_state, branch,
            "chore(unifi-reconciler): update managed-state.json with real UDM ids",
        )

    # Update each policy YAML
    for name, real_id in created_ids.items():
        yaml_path = name_to_file.get(name)
        if not yaml_path or not yaml_path.exists():
            continue
        patched = _patch_yaml_id(yaml_path.read_text(), real_id)
        _gh_put_file(
            token, repo,
            f"{rules_repo_path}/policies/{yaml_path.name}",
            patched, branch,
            f"chore(unifi-reconciler): set real id for '{name}'",
        )

    # Open the PR
    rule_list = "\n".join(f"- `{n}` → `{i}`" for n, i in created_ids.items())
    pr = _gh(token, "POST", f"repos/{repo}/pulls", {
        "title": _WRITEBACK_TITLE,
        "head": branch,
        "base": base_branch,
        "body": (
            "## Automated write-back\n\n"
            "The PostSync reconciler created the following firewall rules on the "
            "UDM and received their real controller-assigned ids. This PR commits "
            "those ids back so subsequent reconcile runs UPDATE rather than "
            "re-CREATE them.\n\n"
            "### Created rules\n\n"
            f"{rule_list}\n\n"
            "**No functional change** — the rules are already live on the "
            "controller. Merge to close the loop."
        ),
    })
    return str(pr["html_url"])
