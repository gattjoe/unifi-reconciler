from unifi_reconciler.diff import ChangeType, build_plan, is_managed
from unifi_reconciler.model import Action, Protocol
from unifi_reconciler.normalized import NormalizedPolicy


def norm(name, *, action=Action.BLOCK, index=10, src="IoT", dst="LAN",
         enabled=True, pid=None, desc="", predefined=False):
    return NormalizedPolicy(
        name=name, enabled=enabled, action=action, index=index, src_zone=src,
        dst_zone=dst, protocol=Protocol.ALL, logging=False, description=desc,
        policy_id=pid, predefined=predefined,
    )


def test_create_when_absent():
    plan = build_plan([norm("a")], [], set())
    assert [c.type for c in plan.changes] == [ChangeType.CREATE]


def test_no_change_when_equal():
    desired = norm("a", pid="p1")
    live = norm("a", pid="p1")
    plan = build_plan([desired], [live], {"p1"})
    assert plan.empty


def test_update_when_field_differs():
    plan = build_plan([norm("a", action=Action.ALLOW, pid="p1")],
                      [norm("a", action=Action.BLOCK, pid="p1")], {"p1"})
    assert [c.type for c in plan.changes] == [ChangeType.UPDATE]
    assert plan.changes[0].policy_id == "p1"


def test_delete_when_owned_and_undesired():
    plan = build_plan([], [norm("a", pid="p1")], {"p1"})
    assert [c.type for c in plan.changes] == [ChangeType.DELETE]
    assert plan.changes[0].policy_id == "p1"


def test_unowned_live_policy_never_touched():
    live = [norm("manual-allow-all", pid="m1"), norm("a", pid="p1")]
    # only id p1 is in the ledger; the manual rule is reported, not changed
    plan = build_plan([], live, {"p1"})
    assert [c.name for c in plan.changes] == ["a"]
    assert plan.unmanaged_names == ["manual-allow-all"]


def test_desired_id_present_live_but_unowned_is_a_conflict():
    # The id exists live but isn't in the ledger: must adopt via export first.
    live = [norm("Block IoT", pid="m1")]
    plan = build_plan([norm("Block IoT", pid="m1")], live, set())
    assert plan.changes == []
    assert plan.conflicts == ["Block IoT"]


def test_duplicate_names_distinct_ids_diff_independently():
    # The regression that drove the id pivot: two rules share a name but have
    # distinct ids — they must match and update independently, not collide.
    live = [norm("K8s Egress URLS", pid="a1"),
            norm("K8s Egress URLS", pid="a2")]
    desired = [norm("K8s Egress URLS", pid="a1"),                     # unchanged
               norm("K8s Egress URLS", action=Action.ALLOW, pid="a2")]  # changed
    plan = build_plan(desired, live, {"a1", "a2"})
    assert [c.type for c in plan.changes] == [ChangeType.UPDATE]
    assert plan.changes[0].policy_id == "a2"


def test_stale_predefined_goes_to_stale_list():
    # Desired has a stale id (no longer on the controller) and a live predefined
    # rule with the same name exists — the controller regenerated the id.
    # Must not attempt CREATE; goes to stale_predefined instead.
    live_predef = norm("Established Traffic", pid="new-id", predefined=True)
    desired = [norm("Established Traffic", pid="old-id")]
    plan = build_plan(desired, [live_predef], set())
    assert plan.stale_predefined == ["Established Traffic"]
    assert plan.changes == []


def test_stale_id_non_predefined_match_still_creates():
    # Same-name live rule exists but is NOT predefined — the YAML's stale id is
    # a genuine adoption gap, so it should still fall through to CREATE.
    live_regular = norm("My Rule", pid="other-id", predefined=False)
    desired = [norm("My Rule", pid="old-id")]
    plan = build_plan(desired, [live_regular], set())
    assert plan.stale_predefined == []
    assert [c.type for c in plan.changes] == [ChangeType.CREATE]


def test_stale_predefined_multiple_rules_all_caught():
    live = [
        norm("Established Traffic", pid="new-1", predefined=True),
        norm("Established Traffic", pid="new-2", predefined=True),
    ]
    desired = [
        norm("Established Traffic", pid="old-1"),
        norm("Established Traffic", pid="old-2"),
    ]
    plan = build_plan(desired, live, set())
    assert plan.stale_predefined == ["Established Traffic", "Established Traffic"]
    assert plan.changes == []


def test_is_managed():
    assert is_managed("x", {"x"})
    assert not is_managed("y", {"x"})
    assert not is_managed(None, {"x"})
