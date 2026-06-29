import pytest

from unifi_reconciler.client import APIError
from unifi_reconciler.diff import Change, ChangeType
from unifi_reconciler.reconcile import ZoneError, _apply_change, reconcile
from unifi_reconciler.safety import SafetyConfig, SafetyError
from tests.conftest import FakeStore, write_policy, write_state
from tests.test_diff import norm


class RespondTrafficStore(FakeStore):
    """FakeStore that raises 'respond traffic' APIError for a specific policy name."""

    def __init__(self, fail_name: str, **kwargs):
        super().__init__(**kwargs)
        self._fail_name = fail_name

    def create_policy(self, desired, zones):
        if desired.name == self._fail_name:
            raise APIError(
                "POST /firewall-policies -> 400 : "
                "Firewall policy create respond traffic not allowed"
            )
        return super().create_policy(desired, zones)

POLICY = """
metadata:
  name: Block IoT
spec:
  action: BLOCK
  index: 10
  source: {zone: IoT}
  destination: {zone: LAN}
"""

LOCKOUT = """
metadata:
  name: Lockout
spec:
  action: BLOCK
  index: 1
  source: {zone: LAN}
  destination: {zone: Gateway}
"""

# Same rule as POLICY but adopted (carries its live id) — for update/no-op tests.
POLICY_P1 = """
metadata:
  name: Block IoT
  id: p1
spec:
  action: BLOCK
  index: 10
  source: {zone: IoT}
  destination: {zone: LAN}
"""


def test_plan_does_not_mutate(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY)
    store = FakeStore()
    result = reconcile(store, rules_dir, apply=False)
    assert not result.applied
    assert store.created == [] and store.updated == [] and store.deleted == []
    assert len(result.plan.changes) == 1


def test_apply_creates(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY)
    store = FakeStore()
    result = reconcile(store, rules_dir, apply=True)
    assert result.applied
    assert [p.name for p in store.created] == ["Block IoT"]


def test_apply_captures_created_ids(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY)
    store = FakeStore()
    result = reconcile(store, rules_dir, apply=True)
    # FakeStore.create_policy returns "new-{name}"
    assert result.created_ids == {"Block IoT": "new-Block IoT"}


def test_apply_is_idempotent(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY_P1)
    write_state(rules_dir, ["p1"])
    live = [norm("Block IoT", index=10, src="IoT", dst="LAN", pid="p1")]
    store = FakeStore(live=live)
    result = reconcile(store, rules_dir, apply=True)
    assert not result.applied  # plan empty
    assert store.created == [] and store.updated == [] and store.deleted == []


def test_unknown_zone_aborts(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY.replace("zone: IoT", "zone: Nonexistent"))
    with pytest.raises(ZoneError):
        reconcile(FakeStore(), rules_dir, apply=True)


def test_safety_blocks_apply(rules_dir):
    write_policy(rules_dir, "lock.yaml", LOCKOUT)
    store = FakeStore()
    with pytest.raises(SafetyError):
        reconcile(store, rules_dir, apply=True,
                  safety_cfg=SafetyConfig(admin_zones=("LAN",)))
    assert store.created == []  # nothing applied before the stop


def test_conflict_with_unowned_live_blocks_apply(rules_dir):
    # The id exists live but isn't in the ledger -> must adopt via export first.
    write_policy(rules_dir, "iot.yaml", POLICY_P1)        # claims id p1
    live = [norm("Block IoT", pid="p1", src="IoT", dst="LAN")]
    store = FakeStore(live=live)                          # but ledger is empty
    with pytest.raises(SafetyError, match="duplicate"):
        reconcile(store, rules_dir, apply=True)
    assert store.created == []


def test_backup_captures_owned_live_only(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY_P1)
    write_state(rules_dir, ["p1"])
    live = [
        norm("Block IoT", pid="p1", src="IoT", dst="LAN"),
        norm("manual-allow", pid="m1"),
    ]
    store = FakeStore(live=live)
    result = reconcile(store, rules_dir, apply=False)
    ids = {b["policy_id"] for b in result.backup}
    assert ids == {"p1"}


def test_delete_runs_after_create(rules_dir):
    # desired has a new (id-less) policy; live has an old owned policy to delete.
    write_policy(rules_dir, "iot.yaml", POLICY)
    write_state(rules_dir, ["old1"])
    live = [norm("Old Rule", pid="old1")]
    store = FakeStore(live=live)
    reconcile(store, rules_dir, apply=True)
    assert [p.name for p in store.created] == ["Block IoT"]
    assert store.deleted == ["old1"]


# _apply_change invariant guards — these states are unreachable via build_plan
# today, but the ValueError ensures future callers fail loudly rather than
# silently passing None into the UDM API.

def test_apply_change_create_requires_desired():
    change = Change(ChangeType.CREATE, "x", None, None)
    with pytest.raises(ValueError, match="no desired policy"):
        _apply_change(FakeStore(), change, {})


def test_apply_change_update_requires_policy_id():
    # live=None means change.policy_id is None
    change = Change(ChangeType.UPDATE, "x", norm("x"), None)
    with pytest.raises(ValueError, match="no policy_id"):
        _apply_change(FakeStore(), change, {})


def test_apply_change_update_requires_desired():
    change = Change(ChangeType.UPDATE, "x", None, norm("x", pid="p1"))
    with pytest.raises(ValueError, match="no desired policy"):
        _apply_change(FakeStore(), change, {})


def test_apply_change_delete_requires_policy_id():
    # live=None means change.policy_id is None
    change = Change(ChangeType.DELETE, "x", None, None)
    with pytest.raises(ValueError, match="no policy_id"):
        _apply_change(FakeStore(), change, {})


RESPOND_TRAFFIC_POLICY = """
metadata:
  name: Established Traffic
spec:
  action: ALLOW
  index: 10095
  source: {zone: IoT}
  destination: {zone: LAN}
"""


def test_respond_traffic_create_is_skipped_not_fatal(rules_dir):
    write_policy(rules_dir, "est.yaml", RESPOND_TRAFFIC_POLICY)
    store = RespondTrafficStore(fail_name="Established Traffic")
    result = reconcile(store, rules_dir, apply=True)
    assert result.applied
    assert result.respond_traffic_skipped == ["Established Traffic"]
    assert store.created == []  # skipped, not applied


def test_respond_traffic_skipped_and_other_rule_still_applies(rules_dir):
    write_policy(rules_dir, "est.yaml", RESPOND_TRAFFIC_POLICY)
    write_policy(rules_dir, "iot.yaml", POLICY)
    store = RespondTrafficStore(fail_name="Established Traffic")
    result = reconcile(store, rules_dir, apply=True)
    assert result.respond_traffic_skipped == ["Established Traffic"]
    assert [p.name for p in store.created] == ["Block IoT"]


def test_non_respond_traffic_api_error_still_propagates(rules_dir):
    write_policy(rules_dir, "iot.yaml", POLICY)

    class BrokenStore(FakeStore):
        def create_policy(self, desired, zones):
            raise APIError("POST /firewall-policies -> 400 : Unknown zone id")

    with pytest.raises(APIError, match="Unknown zone id"):
        reconcile(BrokenStore(), rules_dir, apply=True)
