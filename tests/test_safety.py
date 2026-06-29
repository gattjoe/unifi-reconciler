import pytest

from unifi_reconciler.diff import Change, ChangeType, Plan, build_plan
from unifi_reconciler.model import Action, Protocol
from unifi_reconciler.normalized import NormalizedPolicy
from unifi_reconciler.safety import SafetyConfig, SafetyError, check
from tests.test_diff import norm


def test_clean_plan_passes():
    plan = build_plan([norm("a")], [], set())
    assert check(plan, set()).ok


LAN_CFG = SafetyConfig(admin_zones=("LAN",))


def test_broad_block_from_admin_zone_is_rejected():
    bad = norm("lockout", action=Action.BLOCK, src="LAN", dst="Gateway")
    plan = build_plan([bad], [], set())
    report = check(plan, set(), LAN_CFG)
    assert not report.ok
    with pytest.raises(SafetyError, match="lock"):
        report.raise_if_unsafe()


def test_default_admin_zone_is_internal():
    # The default admin zone is the live LAN-side zone name on this controller.
    bad = norm("lockout", action=Action.BLOCK, src="Internal", dst="Gateway")
    assert not check(build_plan([bad], [], set()), set()).ok


def test_scoped_block_from_admin_zone_is_allowed():
    scoped = NormalizedPolicy(
        name="scoped", enabled=True, action=Action.BLOCK, index=5,
        src_zone="LAN", dst_zone="WAN", protocol=Protocol.ALL, logging=False,
        description="", src_ips=("10.0.5.0/24",),
    )
    plan = build_plan([scoped], [], set())
    assert check(plan, set(), LAN_CFG).ok


def test_disabled_lockout_rule_ignored():
    bad = norm("off", action=Action.BLOCK, src="LAN", enabled=False)
    assert check(build_plan([bad], [], set()), set(), LAN_CFG).ok


def test_delete_protection_guards_unowned():
    # Hand-craft an illegal plan (delete of a name not in the ledger) to prove
    # safety catches it even if diff were ever bypassed.
    live = norm("manual-x", pid="m1")
    illegal = Plan(changes=[Change(ChangeType.DELETE, "manual-x", None, live)])
    report = check(illegal, set())
    assert not report.ok
    assert "unmanaged" in report.violations[0]


def test_conflict_blocks_apply():
    live = [norm("Block IoT", pid="m1")]
    plan = build_plan([norm("Block IoT", pid="m1")], live, set())
    report = check(plan, set())
    assert not report.ok
    assert "duplicate" in report.violations[0]


# ---- admin_networks: scoped-to-network lockout guard --------------------- #
def _nw_norm(name, src_networks, **kw):
    """NormalizedPolicy with src_networks set (within the LAN admin zone)."""
    return NormalizedPolicy(
        name=name, enabled=True, action=Action.BLOCK, index=5,
        src_zone="LAN", dst_zone="Gateway",
        protocol=Protocol.ALL, logging=False, description="",
        src_networks=tuple(src_networks), **kw,
    )


def test_block_scoped_to_admin_network_is_rejected():
    cfg = SafetyConfig(admin_zones=("LAN",), admin_networks=("Management",))
    bad = _nw_norm("scoped-block", src_networks=["Management"])
    assert not check(build_plan([bad], [], set()), set(), cfg).ok


def test_block_scoped_to_non_admin_network_is_allowed():
    cfg = SafetyConfig(admin_zones=("LAN",), admin_networks=("Management",))
    ok = _nw_norm("scoped-ok", src_networks=["Servers"])
    assert check(build_plan([ok], [], set()), set(), cfg).ok


def test_block_scoped_to_network_without_admin_networks_configured_is_allowed():
    # admin_networks empty → network-level check never fires
    cfg = SafetyConfig(admin_zones=("LAN",), admin_networks=())
    ok = _nw_norm("scoped-any", src_networks=["Management"])
    assert check(build_plan([ok], [], set()), set(), cfg).ok


def test_scoped_block_with_src_networks_skips_broad_zone_check():
    # src_networks acts as scoping → the broad-zone check does NOT fire
    # (only the admin_networks check would, and admin_networks is empty here)
    cfg = SafetyConfig(admin_zones=("LAN",), admin_networks=())
    scoped = _nw_norm("block-subset", src_networks=["IoT"])
    assert check(build_plan([scoped], [], set()), set(), cfg).ok


def test_dst_networks_scoping_exempt_from_broad_block_check():
    # dst_networks is symmetric to dst_ips: scoping by destination network
    # is not a lockout risk and should not trigger the broad-zone guard.
    cfg = SafetyConfig(admin_zones=("LAN",), admin_networks=())
    dst_scoped = NormalizedPolicy(
        name="dst-scoped", enabled=True, action=Action.BLOCK, index=5,
        src_zone="LAN", dst_zone="LAN", protocol=Protocol.ALL, logging=False,
        description="", dst_networks=("APP",),
    )
    assert check(build_plan([dst_scoped], [], set()), set(), cfg).ok
