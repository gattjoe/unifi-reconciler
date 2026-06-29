"""Load and validate declarative rule documents from a rules/ directory."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from . import STATE_FILENAME
from .model import FirewallPolicy


class RuleLoadError(RuntimeError):
    pass


def _read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:  # pragma: no cover - thin wrapper
        raise RuleLoadError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleLoadError(f"{path}: expected a mapping at the document root")
    return data


def load_policies(rules_dir: Path) -> list[FirewallPolicy]:
    """Load every ``policies/*.yaml`` document, validate, and check for dupes."""
    policies_dir = rules_dir / "policies"
    if not policies_dir.is_dir():
        return []

    policies: list[FirewallPolicy] = []
    seen_ids: dict[str, Path] = {}
    for path in sorted(policies_dir.glob("*.yaml")):
        raw = _read_yaml(path)
        try:
            policy = FirewallPolicy.model_validate(raw)
        except ValidationError as exc:
            raise RuleLoadError(f"{path}: {exc}") from exc
        # Names are non-unique labels; identity is the controller id. Reject only
        # duplicate ids (two files claiming to manage the same live policy).
        if policy.id is not None:
            if policy.id in seen_ids:
                raise RuleLoadError(
                    f"duplicate policy id {policy.id!r} in {path} and {seen_ids[policy.id]}"
                )
            seen_ids[policy.id] = path
        policies.append(policy)
    return policies


def load_managed_state(rules_dir: Path) -> set[str]:
    """Load the ownership ledger (``managed-state.json``) and return the set of
    policy **ids** the reconciler owns. A missing ledger means *nothing* is owned —
    a safe default: with no ledger the reconciler will neither update nor delete
    any live policy. Run ``unifi-reconciler export`` to populate it."""
    path = rules_dir / STATE_FILENAME
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("managed"), list):
        raise RuleLoadError(
            f"{path}: expected an object with a 'managed' list of {{name, id}} entries"
        )
    ids: set[str] = set()
    for entry in data["managed"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise RuleLoadError(f"{path}: every 'managed' entry needs a string 'id'")
        ids.add(entry["id"])
    return ids


def policy_name_to_file(rules_dir: Path) -> dict[str, Path]:
    """Return {policy_name: yaml_path} for every policy under rules_dir/policies/.
    When names are non-unique the last file (alphabetical) wins — only matters for
    write-back of newly created policies, which should have unique names."""
    policies_dir = rules_dir / "policies"
    if not policies_dir.is_dir():
        return {}
    result: dict[str, Path] = {}
    for path in sorted(policies_dir.glob("*.yaml")):
        try:
            raw = _read_yaml(path)
            policy = FirewallPolicy.model_validate(raw)
        except Exception:
            continue
        result[policy.name] = path
    return result
