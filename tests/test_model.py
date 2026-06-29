import pytest
from pydantic import ValidationError

from unifi_reconciler.model import Action, FirewallPolicy, Protocol


def _doc(name="Block IoT to LAN", **spec):
    base = dict(action="BLOCK", index=10, source={"zone": "IoT"},
                destination={"zone": "LAN"})
    base.update(spec)
    return {"metadata": {"name": name}, "spec": base}


def test_valid_policy_parses():
    p = FirewallPolicy.model_validate(_doc())
    # Real UniFi names (spaces, no prefix) are accepted — ownership keys on the id.
    assert p.name == "Block IoT to LAN"
    assert p.id is None  # optional; absent for not-yet-created rules
    assert p.spec.action == Action.BLOCK
    assert p.spec.protocol == Protocol.ALL  # default


def test_metadata_id_accepted():
    doc = _doc()
    doc["metadata"]["id"] = "6a233c66"
    assert FirewallPolicy.model_validate(doc).id == "6a233c66"


def test_empty_name_rejected():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(_doc(name="   "))


def test_control_char_name_rejected():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(_doc(name="bad\nname"))


def test_unknown_field_rejected():
    doc = _doc()
    doc["spec"]["sproto"] = "tcp"
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(doc)


def test_bad_action_rejected():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(_doc(action="DROP"))


def test_index_bounds():
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(_doc(index=-1))


def test_wrong_kind_rejected():
    doc = _doc()
    doc["kind"] = "TrafficRule"
    with pytest.raises(ValidationError):
        FirewallPolicy.model_validate(doc)


def test_endpoint_networks_field_accepted():
    doc = _doc(source={"zone": "Internal", "networks": ["IOT", "iOS"]})
    p = FirewallPolicy.model_validate(doc)
    assert p.spec.source.networks == ["IOT", "iOS"]


def test_endpoint_networks_defaults_empty():
    p = FirewallPolicy.model_validate(_doc())
    assert p.spec.source.networks == []
    assert p.spec.destination.networks == []
