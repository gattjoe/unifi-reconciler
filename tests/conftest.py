from __future__ import annotations

import json
from pathlib import Path

import pytest

from unifi_reconciler.normalized import NormalizedPolicy


class FakeStore:
    """In-memory PolicyStore for offline tests. Records mutations so tests can
    assert exactly what the reconciler would do against a real UDM."""

    def __init__(self, zones=None, live=None):
        self.zones = zones or {"LAN": "z-lan", "WAN": "z-wan", "IoT": "z-iot", "Guest": "z-guest", "Gateway": "z-gw"}
        self._live = list(live or [])
        self.created: list[NormalizedPolicy] = []
        self.updated: list[tuple[str, NormalizedPolicy]] = []
        self.deleted: list[str] = []

    def list_zones(self):
        return dict(self.zones)

    def list_policies(self):
        return list(self._live)

    def create_policy(self, desired, zones):
        self.created.append(desired)
        return f"new-{desired.name}"

    def update_policy(self, policy_id, desired, zones):
        self.updated.append((policy_id, desired))

    def delete_policy(self, policy_id):
        self.deleted.append(policy_id)


@pytest.fixture
def store():
    return FakeStore()


def write_policy(rules_dir: Path, filename: str, body: str) -> Path:
    pol = rules_dir / "policies"
    pol.mkdir(parents=True, exist_ok=True)
    path = pol / filename
    path.write_text(body)
    return path


def write_state(rules_dir: Path, ids) -> Path:
    """Write the ownership ledger (managed-state.json) keyed on the given ids."""
    path = rules_dir / "managed-state.json"
    path.write_text(json.dumps(
        {"kind": "ManagedState", "managed": [{"name": "", "id": i} for i in ids]}
    ))
    return path


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    (tmp_path / "policies").mkdir()
    return tmp_path
