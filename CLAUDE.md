# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`unifi-reconciler` is a GitOps reconciler for the UniFi UDM SE zone-based firewall: author
policies as YAML, `plan` a diff against the live gateway, `apply` it. Dependency-light
Python CLI (urllib3 + pydantic + PyYAML), src-layout, package `unifi_reconciler`.

## Commands

```bash
make venv     # create .venv and editable-install with [dev] extras
make test     # offline pytest (no UDM needed) — same as: PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m pytest tests/test_diff.py::test_name -q   # single test
ruff check src tests
mypy src
```

Live targets (`make plan|apply|export|introspect|networks`) need these env vars in the
environment or a sourced `.env`: `UDM_HOST`, `UNIFI_USERNAME`, `UNIFI_PASSWORD`,
`UDM_CA_FINGERPRINT` (`UNIFI_SITE` defaults to `default`). `apply` is dry-run unless
`--confirm`/`APPLY=1`. See README for the one-time `UDM_CA_FINGERPRINT` capture.

## Architecture

The pipeline is `loader → normalized → diff → safety → client`, orchestrated by
`reconcile.py` and surfaced by `cli.py`.

- **`normalized.py`** is the spine: a wire-neutral `NormalizedPolicy`. Both desired
  (YAML) and live (UDM) policies are converted to it, so `diff.py` compares apples to
  apples. Touch this carefully — most other modules depend on its shape.
- **`client.py`** (by far the largest, ~780 lines) is the **only** module that knows the
  UniFi wire format — endpoint paths, JSON field names, auth, TLS pinning. The UniFi
  schema expands every release; when a field is wrong on a controller, the fix is almost
  always a one-line edit here, and `unifi-reconciler introspect` shows the real shape. Keep wire
  knowledge confined here; the rest of the package stays wire-neutral and unit-tested.
- **`model.py`** is the human-facing pydantic schema (`FirewallPolicy` YAML contract);
  **`loader.py`** reads/validates the rules dir; **`config.py`** sources runtime config
  from env vars.
- **`diff.py`** computes the desired-vs-live plan over the *owned subset only*.
- **`safety.py`** holds pre-apply guardrails — any violation is a hard stop (`SafetyError`),
  not a warning, because a firewall mistake can lock you out of the gateway.
- **`export.py`** adopts existing live rules into YAML + the ledger; **`writeback.py`**
  persists controller-assigned IDs after a v2 create (local file edit or a GitHub PR).

## Two invariants that drive the whole design

1. **Ownership is an explicit ledger.** The tool mutates *only* policies whose `id`/`name`
   appears in `managed-state.json`. UI-made and predefined rules are invisible until
   adopted via `export`. Ownership keys on the controller's stable `_id`, not the name.

2. **The declarative model is a lossy subset.** A live policy can carry fields the model
   doesn't represent (connection states, ip-version, schedules, port/IP groups, ICMP
   types). `apply` sends only modeled fields, so adopting a rule that uses an unmodeled
   field would *strip* it — and `plan` won't warn. `export` is the only place this shows
   (`[LOSSY: …]`). To support a new field: extend `model.py` **and** its mapping in
   `client.py` together.

v2 **create is intentionally unsupported** (the v2 `matching_target` union can't be
expressed in the model) — new rules are authored in the UI and adopted via `export`.

## CLI exit codes (set in `cli.py:main`)

`1` config/rule/zone error · `2` apply without confirm · `3` SAFETY STOP · `4` TLS pin
failure · `5` API error · `6` write-back error.
