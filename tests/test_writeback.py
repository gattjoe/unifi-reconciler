"""Tests for writeback.py — local file write-back and GitHub API PR logic."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from unifi_reconciler.writeback import (
    WritebackError,
    _gh_file_sha,
    _patch_yaml_id,
    _updated_state_json,
    _validate_id,
    write_locally,
)


# --------------------------------------------------------------------------- #
# _patch_yaml_id
# --------------------------------------------------------------------------- #

YAML_WITH_ID = """\
apiVersion: firewall.echobase.network/v1
kind: FirewallPolicy
metadata:
  name: Allow Apps
  id: fake-placeholder-9999
spec:
  enabled: true
"""

YAML_WITHOUT_ID = """\
apiVersion: firewall.echobase.network/v1
kind: FirewallPolicy
metadata:
  name: Allow Apps
spec:
  enabled: true
"""


def test_patch_yaml_id_replaces_existing():
    result = _patch_yaml_id(YAML_WITH_ID, "real-abc123")
    assert "  id: real-abc123" in result
    assert "fake-placeholder-9999" not in result


def test_patch_yaml_id_inserts_when_absent():
    result = _patch_yaml_id(YAML_WITHOUT_ID, "real-abc123")
    assert "  id: real-abc123" in result


def test_patch_yaml_id_preserves_rest():
    result = _patch_yaml_id(YAML_WITH_ID, "real-abc123")
    assert "Allow Apps" in result
    assert "enabled: true" in result


def test_patch_yaml_id_only_touches_metadata_id():
    yaml = "metadata:\n  name: foo\n  id: old\nspec:\n  description: has id: something\n"
    result = _patch_yaml_id(yaml, "new-id")
    assert result.count("new-id") == 1
    assert "has id: something" in result


def test_patch_yaml_id_safe_with_regex_metacharacters():
    # Real IDs never look like this, but the replacement must be literal regardless.
    for tricky in (r"\g<1>injected", r"\1", r"\\", r"\n"):
        result = _patch_yaml_id(YAML_WITH_ID, tricky)
        assert tricky in result
        assert "fake-placeholder-9999" not in result


# --------------------------------------------------------------------------- #
# _validate_id
# --------------------------------------------------------------------------- #

def test_validate_id_accepts_normal_ids():
    _validate_id("abc123", "rule")
    _validate_id("6843f2a1b8e3d40001c7a4f2", "rule")
    _validate_id("some-rule_id", "rule")


def test_validate_id_rejects_special_chars():
    for bad in (r"\g<1>", "id with spaces", "id:colon", "id\nnewline", "id{brace}"):
        with pytest.raises(WritebackError, match="unsafe policy id"):
            _validate_id(bad, "rule")


# --------------------------------------------------------------------------- #
# _gh_file_sha 404 handling
# --------------------------------------------------------------------------- #

def test_gh_file_sha_returns_empty_on_404():
    with patch("unifi_reconciler.writeback._gh") as mock_gh:
        mock_gh.side_effect = WritebackError("GitHub API GET repos/x/contents/y: HTTP 404 — not found")
        result = _gh_file_sha("tok", "owner/repo", "some/path", "main")
    assert result == ""


def test_gh_file_sha_reraises_non_404():
    with patch("unifi_reconciler.writeback._gh") as mock_gh:
        mock_gh.side_effect = WritebackError("GitHub API GET repos/x/contents/y: HTTP 500 — server error")
        with pytest.raises(WritebackError, match="HTTP 500"):
            _gh_file_sha("tok", "owner/repo", "some/path", "main")


# --------------------------------------------------------------------------- #
# _updated_state_json
# --------------------------------------------------------------------------- #

def _state_file(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "managed-state.json"
    path.write_text(json.dumps(
        {"apiVersion": "firewall.echobase.network/v1", "kind": "ManagedState",
         "managed": entries}
    ))
    return path


def test_updated_state_json_replaces_placeholder(tmp_path):
    state = _state_file(tmp_path, [
        {"name": "Allow Apps", "id": "fake-9999"},
        {"name": "Block IoT", "id": "real-existing"},
    ])
    result = _updated_state_json(state, {"Allow Apps": "real-abc123"})
    data = json.loads(result)
    by_name = {e["name"]: e["id"] for e in data["managed"]}
    assert by_name["Allow Apps"] == "real-abc123"
    assert by_name["Block IoT"] == "real-existing"


def test_updated_state_json_leaves_unrelated_entries(tmp_path):
    state = _state_file(tmp_path, [
        {"name": "Allow Apps", "id": "fake-9999"},
        {"name": "Block IoT", "id": "abc"},
        {"name": "Another Rule", "id": "def"},
    ])
    result = _updated_state_json(state, {"Allow Apps": "new-id"})
    data = json.loads(result)
    assert len(data["managed"]) == 3


# --------------------------------------------------------------------------- #
# write_locally
# --------------------------------------------------------------------------- #

def test_write_locally_updates_state_and_yaml(tmp_path):
    (tmp_path / "policies").mkdir()
    state = _state_file(tmp_path, [{"name": "Allow Apps", "id": "fake-9999"}])
    yaml_path = tmp_path / "policies" / "allow-apps.yaml"
    yaml_path.write_text(YAML_WITH_ID)

    changed = write_locally(
        tmp_path,
        {"Allow Apps": "real-abc123"},
        {"Allow Apps": yaml_path},
    )

    assert state in changed
    assert yaml_path in changed
    assert "real-abc123" in state.read_text()
    assert "real-abc123" in yaml_path.read_text()
    assert "fake-placeholder-9999" not in yaml_path.read_text()


def test_write_locally_skips_missing_yaml(tmp_path):
    (tmp_path / "policies").mkdir()
    _state_file(tmp_path, [{"name": "Allow Apps", "id": "fake"}])
    # no yaml_path in name_to_file
    changed = write_locally(tmp_path, {"Allow Apps": "real-id"}, {})
    # state still updated; yaml silently skipped
    assert len(changed) == 1


def test_write_locally_rejects_unsafe_id(tmp_path):
    (tmp_path / "policies").mkdir()
    _state_file(tmp_path, [{"name": "Allow Apps", "id": "fake"}])
    with pytest.raises(WritebackError, match="unsafe policy id"):
        write_locally(tmp_path, {"Allow Apps": "bad\nid"}, {})


def test_write_locally_no_op_when_content_unchanged(tmp_path):
    (tmp_path / "policies").mkdir()
    # Write the state file in the same format write_locally produces so the
    # string comparison in write_locally correctly detects no change.
    state = tmp_path / "managed-state.json"
    entries = [{"name": "Allow Apps", "id": "already-real"}]
    state.write_text(
        json.dumps(
            {"apiVersion": "firewall.echobase.network/v1", "kind": "ManagedState",
             "managed": entries},
            indent=2, ensure_ascii=False,
        ) + "\n"
    )
    yaml_path = tmp_path / "policies" / "allow-apps.yaml"
    yaml_path.write_text(YAML_WITH_ID.replace("fake-placeholder-9999", "already-real"))

    changed = write_locally(
        tmp_path,
        {"Allow Apps": "already-real"},
        {"Allow Apps": yaml_path},
    )
    assert changed == []
