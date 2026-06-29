"""Command-line entrypoint: ``unifi-reconciler plan|apply|introspect``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .client import APIError, SecurityError, UniFiClient
from .config import ConfigError, load
from .diff import ChangeType, Plan
from .export import collect, write_export
from .loader import RuleLoadError, policy_name_to_file
from .reconcile import ReconcileResult, ZoneError, backup_json, reconcile
from .safety import SafetyConfig, SafetyError
from .writeback import WritebackError, open_github_pr, write_locally

_SYMBOL = {ChangeType.CREATE: "+ create", ChangeType.UPDATE: "~ update", ChangeType.DELETE: "- delete"}


def _render_plan(plan: Plan) -> str:
    lines: list[str] = []
    if plan.empty:
        lines.append("No changes. Managed firewall policies are up to date.")
    else:
        lines.append(f"Plan: {len(plan.of(ChangeType.CREATE))} to create, "
                     f"{len(plan.of(ChangeType.UPDATE))} to update, "
                     f"{len(plan.of(ChangeType.DELETE))} to delete.\n")
        for c in plan.changes:
            lines.append(f"  {_SYMBOL[c.type]}  {c.name}")
            if c.type == ChangeType.UPDATE and c.desired and c.live:
                for label, want, have in _field_diffs(c.desired, c.live):
                    lines.append(f"        {label}: {have!r} -> {want!r}")
    if plan.unmanaged_names:
        lines.append(f"\n  ({len(plan.unmanaged_names)} unmanaged policy(ies) left "
                     "untouched: " + ", ".join(plan.unmanaged_names) + ")")
    if plan.conflicts:
        lines.append("\n  CONFLICT: " + ", ".join(plan.conflicts) + " — these names "
                     "match live policies not in the ledger; run `unifi-reconciler export` to "
                     "adopt them before they can be managed.")
    if plan.stale_predefined:
        lines.append("\n  STALE IDs (predefined): " + ", ".join(plan.stale_predefined)
                     + " — the controller regenerated the id for these predefined rules "
                     "(e.g. after a firmware update). Re-run `unifi-reconciler export` to adopt "
                     "the new ids, then commit the updated YAML + managed-state.json.")
    return "\n".join(lines)


def _field_diffs(want, have):
    out = []
    for label in ("enabled", "action", "src_zone", "dst_zone", "protocol",
                  "logging", "src_networks", "dst_networks"):
        w, h = getattr(want, label), getattr(have, label)
        if w != h:
            out.append((label, w, h))
    # Optional fields: only surface when explicitly set in desired (not None / empty),
    # so plan output doesn't show noise for rules that have no opinion on them.
    for label in ("connection_state_type", "connection_states", "ip_version", "auto_return_traffic"):
        w = getattr(want, label)
        if w is not None and w != ():
            h = getattr(have, label)
            if w != h:
                out.append((label, w, h))
    return out


def _build_client(args):
    cfg = load()
    return UniFiClient(cfg), cfg


def _cmd_plan(args) -> int:
    client, cfg = _build_client(args)
    with client:
        result = reconcile(client, Path(args.rules), apply=False,
                           safety_cfg=SafetyConfig(admin_zones=cfg.admin_zones,
                                                   admin_networks=cfg.admin_networks,
                                                   admin_dst_zones=cfg.admin_dst_zones))
    print(_render_plan(result.plan))
    return 0


def _cmd_apply(args) -> int:
    if not (args.confirm or _env_confirm()):
        print("apply requires --confirm (or APPLY=1). Refusing.", file=sys.stderr)
        return 2
    client, cfg = _build_client(args)
    with client:
        result: ReconcileResult = reconcile(
            client, Path(args.rules), apply=True,
            safety_cfg=SafetyConfig(admin_zones=cfg.admin_zones,
                                    admin_networks=cfg.admin_networks,
                                    admin_dst_zones=cfg.admin_dst_zones))
    if args.backup_file and result.backup:
        Path(args.backup_file).write_text(backup_json(result))
        print(f"[unifi-reconciler] pre-change backup written to {args.backup_file}")
    print(_render_plan(result.plan))
    print("\nApplied." if result.applied else "\nNothing to apply.")

    if result.respond_traffic_skipped:
        print("\nWARNING: skipped CREATE for respond-traffic rule(s): "
              + ", ".join(result.respond_traffic_skipped)
              + "\n  These are predefined controller rules with stale IDs in your YAML. "
              "Re-run `unifi-reconciler export` to adopt the current IDs, then commit the "
              "updated YAML + managed-state.json.", file=sys.stderr)

    if result.applied and result.created_ids:
        rules_dir = Path(args.rules)
        name_to_file = policy_name_to_file(rules_dir)
        if cfg.github_token and cfg.github_repo:
            try:
                pr_url = open_github_pr(
                    token=cfg.github_token,
                    repo=cfg.github_repo,
                    rules_dir=rules_dir,
                    rules_repo_path=cfg.github_rules_path,
                    base_branch=cfg.github_base_branch,
                    created_ids=result.created_ids,
                    name_to_file=name_to_file,
                )
                print(f"\nWrite-back PR: {pr_url}")
                print("Merge it to persist the real ids — until then the next sync "
                      "will re-create the rules.")
            except WritebackError as exc:
                print(f"\nWARNING: write-back PR failed: {exc}", file=sys.stderr)
                print("Real ids (commit these manually):", file=sys.stderr)
                for name, uid in result.created_ids.items():
                    print(f"  {name}: {uid}", file=sys.stderr)
                return 6
        else:
            changed = write_locally(rules_dir, result.created_ids, name_to_file)
            print("\nReal ids written back locally. Commit before the next sync:")
            for path in changed:
                print(f"  {path}")

    return 0


def _cmd_introspect(args) -> int:
    client, _ = _build_client(args)
    with client:
        print(json.dumps(client.raw_policies(), indent=2))
    return 0


def _cmd_networks(args) -> int:
    client, _ = _build_client(args)
    with client:
        nets = client.list_networks()
    print(f"{len(nets)} network(s) (zone <- network membership):")
    for n in nets:
        vlan = f"vlan {n.vlan}" if n.vlan is not None else "untagged"
        print(f"  {n.zone or '(none)':10} {vlan:9} {n.cidr or '-':18} "
              f"{n.name}  [{n.purpose}]")
    if args.write:
        from .networks import render_networks_yaml
        out = Path(args.rules) / "networks.yaml"
        out.write_text(render_networks_yaml(nets))
        print(f"\nWrote {out} — fill in the TODO fields (trust/description/"
              "internet/key_hosts).")
    return 0


def _cmd_export(args) -> int:
    client, _ = _build_client(args)
    with client:
        zones_by_id = {v: k for k, v in client.list_zones().items()}
        raw = client.raw_policies() or []
        networks_by_id = client._networks_by_id()
    plan = collect(raw, zones_by_id, networks_by_id)

    print(f"Discovered {len(plan.policies)} manageable policy(ies)"
          + (f", skipped {len(plan.skipped_predefined)} predefined"
             if plan.skipped_predefined else "") + ".")
    for e in plan.policies:
        flag = f"  [LOSSY: {', '.join(e.unmodeled)}]" if e.unmodeled else ""
        print(f"  {e.filename:<40} {e.policy.name}{flag}")
    if plan.has_lossy:
        print("\nWARNING: rules marked [LOSSY] carry fields this model does not "
              "represent; apply would NOT preserve them. Review export-raw.json "
              "and extend the model before letting apply touch those rules.")

    if args.dry_run:
        print("\nDry run — no files written.")
        return 0

    out = Path(args.out) if args.out else Path(args.rules)
    written = write_export(plan, out, write_zones=args.write_zones)
    print(f"\nWrote {len(written)} file(s) under {out}:")
    for path in written:
        print(f"  {path}")
    print("\nNext: review the diff (especially export-raw.json), commit, then "
          "`make plan` should report no changes (rules now match live).")
    return 0


def _env_confirm() -> bool:
    import os

    return os.environ.get("APPLY", "").lower() in ("1", "true", "yes")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unifi-reconciler", description=__doc__)
    p.add_argument("--version", action="version", version=f"unifi-reconciler {__version__}")
    p.add_argument("--rules", default="rules", help="path to the rules/ directory")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("plan", help="read-only diff (default-safe)").set_defaults(func=_cmd_plan)

    ap = sub.add_parser("apply", help="apply the plan (mutating)")
    ap.add_argument("--confirm", action="store_true", help="required to mutate")
    ap.add_argument("--backup-file", default="", help="write pre-change backup JSON here")
    ap.set_defaults(func=_cmd_apply)

    sub.add_parser("introspect", help="dump one raw live policy set for schema checks"
                   ).set_defaults(func=_cmd_introspect)

    nw = sub.add_parser("networks", help="read-only: list L3 networks and their "
                        "firewall zones (context for rule analysis)")
    nw.add_argument("--write", action="store_true",
                    help="scaffold networks.yaml under --rules from the live map")
    nw.set_defaults(func=_cmd_networks)

    ex = sub.add_parser("export", help="import live policies into YAML + the ledger")
    ex.add_argument("--out", default="", help="output dir (default: --rules dir)")
    ex.add_argument("--write-zones", action="store_true",
                    help="(over)write zones.yaml from live zones (drops purposes)")
    ex.add_argument("--dry-run", action="store_true",
                    help="print what would be exported without writing files")
    ex.set_defaults(func=_cmd_export)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, RuleLoadError, ZoneError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except SafetyError as exc:
        print(f"SAFETY STOP: {exc}", file=sys.stderr)
        return 3
    except SecurityError as exc:
        print(f"TLS PIN FAILURE: {exc}", file=sys.stderr)
        return 4
    except APIError as exc:
        print(f"API error: {exc}", file=sys.stderr)
        return 5
    except WritebackError as exc:
        print(f"write-back error: {exc}", file=sys.stderr)
        return 6


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
