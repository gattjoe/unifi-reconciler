from types import SimpleNamespace

import pytest
import urllib3

from unifi_reconciler.client import (
    APIError,
    UniFiClient,
    _read_ports,
    build_path,
    merge_desired_into_v2,
    policy_from_wire,
    policy_to_wire_v2_create,
)
from unifi_reconciler.config import ConfigError, load
from unifi_reconciler.model import Action, Protocol
from unifi_reconciler.normalized import NormalizedPolicy

ZONES = {"LAN": "z-lan", "IoT": "z-iot"}
ZONES_BY_ID = {v: k for k, v in ZONES.items()}

TEMPLATE = "/proxy/network/v2/api/site/{site}/firewall-policies/{id}"


def test_build_path_encodes_segments():
    # A malicious id must not break out of its path segment.
    p = build_path(TEMPLATE, site="default", id="../../zones")
    assert "/firewall-policies/..%2F..%2Fzones" in p
    assert "/zones" != p[-6:]  # the traversal did not retarget to a real endpoint


def test_build_path_normal_values():
    p = build_path(TEMPLATE, site="default", id="abc123")
    assert p.endswith("/site/default/firewall-policies/abc123")


# ---- site validation (config) -------------------------------------------- #
BASE_ENV = {"UDM_HOST": "1.2.3.4", "UDM_CA_FINGERPRINT": "ab"}


def test_site_default_ok():
    cfg = load(BASE_ENV)
    assert cfg.site == "default"


def test_site_rejects_path_chars():
    with pytest.raises(ConfigError, match="UNIFI_SITE"):
        load({**BASE_ENV, "UNIFI_SITE": "a/b/../c"})


def test_missing_fingerprint_fails_closed():
    env = {"UDM_HOST": "1.2.3.4"}
    with pytest.raises(ConfigError, match="UDM_CA_FINGERPRINT"):
        load(env)


# ---- error-detail extraction (no raw body) -------------------------------- #
class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        if self._payload is _BAD:
            raise ValueError("not json")
        return self._payload


_BAD = object()


def test_error_detail_extracts_known_field():
    from unifi_reconciler.client import UniFiClient

    assert UniFiClient._error_detail(FakeResp({"message": "zone not found"})) == ": zone not found"
    assert UniFiClient._error_detail(FakeResp({"meta": {"msg": "api.err.Invalid"}})) == ": api.err.Invalid"


def test_error_detail_ignores_unknown_and_nonjson():
    from unifi_reconciler.client import UniFiClient

    assert UniFiClient._error_detail(FakeResp({"secret_token": "leak-me"})) == ""
    assert UniFiClient._error_detail(FakeResp(_BAD)) == ""


# ---- mapping round-trip sanity ------------------------------------------- #
def test_from_wire_resolves_zone_names():
    raw = {"id": "p1", "name": "gitops-x", "action": "BLOCK", "index": 5,
           "source": {"zone_id": "z-iot"}, "destination": {"zone_id": "z-lan"}}
    n = policy_from_wire(raw, ZONES_BY_ID)
    assert n.src_zone == "IoT" and n.dst_zone == "LAN" and n.policy_id == "p1"


def test_from_wire_reads_v2_underscore_id():
    # The internal v2 surface returns the id as "_id", not "id".
    raw = {"_id": "v2id", "name": "x", "action": "BLOCK", "index": 1,
           "source": {"zone_id": "z-lan"}, "destination": {"zone_id": "z-iot"}}
    assert policy_from_wire(raw, ZONES_BY_ID).policy_id == "v2id"


# ---- v2 cookie+CSRF session ---------------------------------------------- #
V2_ENV = {
    "UDM_HOST": "1.2.3.4",
    "UDM_CA_FINGERPRINT": "ab",
    "UNIFI_USERNAME": "admin",
    "UNIFI_PASSWORD": "pw",
    "UNIFI_SITE": "testsite",
}


class _Resp:
    """Minimal urllib3-like response with case-insensitive headers."""

    def __init__(self, status=200, *, headers=None, body=None, reason="OK"):
        self.status = status
        self.reason = reason
        self._body = body
        self.headers = urllib3.HTTPHeaderDict(headers or {})

    @property
    def data(self):
        return b"x" if self._body is not None else b""

    def json(self):
        return self._body


class _FakeHTTP:
    """Records requests and returns queued responses in order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, *, json=None, headers=None, **kw):
        self.calls.append(SimpleNamespace(method=method, url=url, json=json, headers=headers))
        return self._responses.pop(0)

    def clear(self):
        pass


def _login_resp(token="tok", csrf="csrf1"):
    return _Resp(headers={"Set-Cookie": f"TOKEN={token}; Path=/; HttpOnly",
                          "X-Updated-CSRF-Token": csrf})


def test_v2_login_captures_token_and_csrf_and_injects_them():
    http = _FakeHTTP([_login_resp(), _Resp(body=[{"name": "LAN", "_id": "z-lan"}])])
    client = UniFiClient(load(V2_ENV), http=http)

    zones = client.list_zones()

    assert zones == {"LAN": "z-lan"}
    assert client._token == "tok" and client._csrf == "csrf1"
    login, zones_get = http.calls
    assert login.method == "POST" and login.url.endswith("/api/auth/login")
    assert login.json == {"username": "admin", "password": "pw", "rememberMe": True}
    assert zones_get.headers["Cookie"] == "TOKEN=tok"
    assert zones_get.headers["X-CSRF-Token"] == "csrf1"
    # v2 addresses the site by its shortname, not the opaque integration id.
    assert "/site/testsite/" in zones_get.url


def test_v2_csrf_rotates_across_requests():
    http = _FakeHTTP([
        _login_resp(csrf="csrf1"),
        _Resp(body=[{"name": "LAN", "_id": "z-lan"}],
              headers={"X-Updated-CSRF-Token": "csrf2"}),
        _Resp(body=[]),
    ])
    client = UniFiClient(load(V2_ENV), http=http)

    client.list_policies()  # login -> GET zones -> GET policies

    _, zones_get, policies_get = http.calls
    assert zones_get.headers["X-CSRF-Token"] == "csrf1"
    # the rotated token from the zones response must carry into the next call
    assert policies_get.headers["X-CSRF-Token"] == "csrf2"
    assert client._csrf == "csrf2"


def test_v2_login_failure_raises():
    http = _FakeHTTP([_Resp(401, reason="Unauthorized", body={"message": "bad creds"})])
    client = UniFiClient(load(V2_ENV), http=http)
    with pytest.raises(APIError, match="v2 login"):
        client.list_zones()


def test_v2_login_without_token_cookie_raises():
    http = _FakeHTTP([_Resp(headers={"X-Updated-CSRF-Token": "csrf1"})])  # no Set-Cookie
    client = UniFiClient(load(V2_ENV), http=http)
    with pytest.raises(APIError, match="no TOKEN cookie"):
        client.list_zones()


# ---- _read_ports helper -------------------------------------------------- #

def test_read_ports_from_plural():
    assert _read_ports({"ports": ["80", "443"]}) == ("80", "443")


def test_read_ports_from_singular_scalar():
    # Older firmware stores a single port as "port": 443 (integer scalar).
    assert _read_ports({"port": 443}) == ("443",)


def test_read_ports_from_singular_string():
    assert _read_ports({"port": "8080"}) == ("8080",)


def test_read_ports_plural_takes_precedence_over_singular():
    assert _read_ports({"ports": ["443"], "port": "80"}) == ("443",)


def test_read_ports_empty_when_neither_key():
    assert _read_ports({}) == ()


def test_policy_from_wire_reads_singular_port():
    raw = {
        "_id": "px", "name": "R", "enabled": True, "action": "ALLOW", "index": 1,
        "protocol": "all", "logging": False,
        "source": {"zone_id": "z-lan"},
        "destination": {"zone_id": "z-lan", "port": "443"},
    }
    p = policy_from_wire(raw, {"LAN": "z-lan"})
    assert p.dst_ports == ("443",)
    assert p.src_ports == ()


# ---- v2 read-modify-write update + delete + create gate ------------------ #
V2_ZONES = {"Internal": "z-int", "External": "z-ext"}

# A live CLIENT-target rule: the union specifics (client_macs, schedule, …) must
# survive an update that only changes modeled scalar fields.
RAW_CLIENT = {
    "_id": "p1", "name": "Kids Allowed", "enabled": True, "action": "ALLOW",
    "index": 5, "logging": False, "protocol": "all", "connection_state_type": "ALL",
    "connection_states": [], "ip_version": "BOTH", "match_opposite_protocol": False,
    "schedule": {"mode": "ALWAYS"},
    "source": {"matching_target": "CLIENT", "matching_target_type": "SPECIFIC",
               "client_macs": ["aa:bb:cc:dd:ee:ff"], "port_matching_type": "ANY",
               "match_opposite_ports": False, "zone_id": "z-old"},
    "destination": {"matching_target": "ANY", "port_matching_type": "ANY",
                    "match_opposite_ports": False, "zone_id": "z-old2"},
}

RAW_IP = {
    "_id": "p2", "name": "Allow parent", "enabled": True, "action": "ALLOW", "index": 1,
    "logging": False, "protocol": "all",
    "source": {"matching_target": "ANY", "zone_id": "z-old"},
    "destination": {"matching_target": "IP", "ips": ["192.168.3.5"], "port": "443",
                    "port_matching_type": "SPECIFIC", "zone_id": "z-old2"},
}

# A NETWORK-target rule: source scoped to specific network_ids.
RAW_NETWORK = {
    "_id": "p3", "name": "Block IOT to APP", "enabled": True, "action": "BLOCK",
    "index": 5000, "logging": False, "protocol": "all",
    "source": {"matching_target": "NETWORK", "network_ids": ["n-iot", "n-ios"],
               "zone_id": "z-int"},
    "destination": {"matching_target": "NETWORK", "network_ids": ["n-app"],
                    "zone_id": "z-int"},
}

V2_NETWORKS = {"IOT": "n-iot", "iOS": "n-ios", "APP": "n-app"}
V2_NETWORKS_BY_ID = {v: k for k, v in V2_NETWORKS.items()}

RAW_WEB = {
    "_id": "pw", "name": "Block YT", "enabled": True, "action": "BLOCK", "index": 1,
    "logging": False, "protocol": "all",
    "source": {"matching_target": "ANY", "zone_id": "z-int"},
    "destination": {"matching_target": "WEB", "web_domains": ["youtube.com", "youtu.be"],
                    "web_matching_type": "DOMAIN", "zone_id": "z-ext"},
}

RAW_APP = {
    "_id": "pa", "name": "Block App", "enabled": True, "action": "BLOCK", "index": 2,
    "logging": False, "protocol": "all",
    "source": {"matching_target": "ANY", "zone_id": "z-int"},
    "destination": {"matching_target": "APP", "app_ids": ["app-yt", "app-fb"],
                    "zone_id": "z-ext"},
}

RAW_APP_CAT = {
    "_id": "pc", "name": "Block Cat", "enabled": True, "action": "BLOCK", "index": 3,
    "logging": False, "protocol": "all",
    "source": {"matching_target": "ANY", "zone_id": "z-int"},
    "destination": {"matching_target": "APP_CATEGORY", "app_category_ids": ["cat-social"],
                    "zone_id": "z-ext"},
}

V2_ZONES_INT = {"Internal": "z-int", "External": "z-ext"}


def _np(name, *, src_networks=(), dst_networks=(),
        src_app_ids=(), dst_app_ids=(),
        src_app_category_ids=(), dst_app_category_ids=(),
        src_web_domains=(), dst_web_domains=(),
        src_web_matching_type="", dst_web_matching_type="",
        src_macs=(), dst_macs=(),
        **kw):
    base = dict(enabled=True, action=Action.ALLOW, index=5, src_zone="Internal",
                dst_zone="External", protocol=Protocol.ALL, logging=False, description="",
                src_networks=src_networks, dst_networks=dst_networks,
                src_app_ids=src_app_ids, dst_app_ids=dst_app_ids,
                src_app_category_ids=src_app_category_ids, dst_app_category_ids=dst_app_category_ids,
                src_web_domains=src_web_domains, dst_web_domains=dst_web_domains,
                src_web_matching_type=src_web_matching_type, dst_web_matching_type=dst_web_matching_type,
                src_macs=src_macs, dst_macs=dst_macs)
    base.update(kw)
    return NormalizedPolicy(name=name, **base)


def test_merge_preserves_union_and_overlays_scalars():
    desired = _np("Kids Allowed", enabled=False, action=Action.BLOCK, index=9, logging=True)
    out = merge_desired_into_v2(RAW_CLIENT, desired, V2_ZONES)
    # modeled scalars overlaid
    assert (out["enabled"], out["action"], out["index"], out["logging"]) == (False, "BLOCK", 9, True)
    # zones retargeted by name -> id
    assert out["source"]["zone_id"] == "z-int" and out["destination"]["zone_id"] == "z-ext"
    # union specifics + v2-only fields preserved verbatim
    assert out["source"]["matching_target"] == "CLIENT"
    assert out["source"]["client_macs"] == ["aa:bb:cc:dd:ee:ff"]
    assert out["schedule"] == {"mode": "ALWAYS"}
    assert "description" not in out
    # input not mutated (deep copy)
    assert RAW_CLIENT["enabled"] is True and RAW_CLIENT["source"]["zone_id"] == "z-old"


def test_merge_overlays_ips_only_for_ip_target():
    desired = _np("Allow parent", dst_ips=("10.0.0.9",))
    out = merge_desired_into_v2(RAW_IP, desired, V2_ZONES)
    assert out["destination"]["ips"] == ["10.0.0.9"]       # IP side gets overlaid
    # desired has no ports → live port: "443" is cleared and port_matching_type reset
    assert "port" not in out["destination"]
    assert out["destination"]["port_matching_type"] == "ANY"
    assert "ips" not in out["source"]                       # ANY side left alone


def test_merge_applies_dst_ports():
    desired = _np("Allow parent", dst_ips=("10.0.0.9",), dst_ports=("8443",))
    out = merge_desired_into_v2(RAW_IP, desired, V2_ZONES)
    # IP-target rules use scalar "port", not "ports" array
    assert out["destination"]["port"] == "8443"
    assert "ports" not in out["destination"]
    assert out["destination"]["port_matching_type"] == "SPECIFIC"
    assert out["destination"]["match_opposite_ports"] is False


def test_merge_clears_live_port_when_desired_has_no_ports():
    desired = _np("Allow parent", dst_ips=("10.0.0.9",))
    out = merge_desired_into_v2(RAW_IP, desired, V2_ZONES)
    assert "port" not in out["destination"]
    assert "ports" not in out["destination"]
    assert out["destination"]["port_matching_type"] == "ANY"


def test_merge_rejects_unknown_zone():
    with pytest.raises(APIError, match="unknown zone"):
        merge_desired_into_v2(RAW_CLIENT, _np("x", src_zone="Nope"), V2_ZONES)


def test_v2_update_is_read_modify_write():
    http = _FakeHTTP([
        _login_resp(),
        _Resp(body=RAW_CLIENT),                 # GET-by-id
        _Resp(body={"_id": "p1"}),              # PUT
    ])
    client = UniFiClient(load(V2_ENV), http=http)
    client.update_policy("p1", _np("Kids Allowed", enabled=False), V2_ZONES)
    _, get_call, put_call = http.calls
    assert get_call.method == "GET" and get_call.url.endswith("/firewall-policies/p1")
    assert put_call.method == "PUT" and put_call.url.endswith("/firewall-policies/p1")
    # the PUT body is the merged object: scalar changed, union preserved
    assert put_call.json["enabled"] is False
    assert put_call.json["source"]["client_macs"] == ["aa:bb:cc:dd:ee:ff"]


def test_v2_update_refuses_when_live_fetch_is_empty():
    # An anomalous empty/204 GET-by-id must NOT lead to a PUT of a body
    # reconstructed from nothing (which would strip the matching_target union).
    http = _FakeHTTP([_login_resp(), _Resp(status=204)])   # login, then empty GET
    client = UniFiClient(load(V2_ENV), http=http)
    with pytest.raises(APIError, match="could not fetch live policy"):
        client.update_policy("p1", _np("Kids Allowed", enabled=False), V2_ZONES)
    # the GET happened, but no PUT was issued
    assert [c.method for c in http.calls] == ["POST", "GET"]


def test_v2_delete_issues_delete():
    http = _FakeHTTP([_login_resp(), _Resp(status=204)])
    client = UniFiClient(load(V2_ENV), http=http)
    client.delete_policy("p9")
    assert http.calls[-1].method == "DELETE"
    assert http.calls[-1].url.endswith("/firewall-policies/p9")


def test_v2_create_wire_any_target():
    body = policy_to_wire_v2_create(_np("New Rule"), V2_ZONES)
    assert body["source"]["matching_target"] == "ANY"
    assert body["destination"]["matching_target"] == "ANY"
    assert "description" not in body
    # Required top-level fields must be present so the controller's bean validator accepts the body.
    assert body["ip_version"] == "IPV4"
    assert body["connection_state_type"] == "CUSTOM"
    assert body["connection_states"] == ["NEW"]
    assert body["create_allow_respond"] is False
    assert body["match_opposite_protocol"] is False
    # Per-side required fields.
    assert body["source"]["matching_target_type"] == "SPECIFIC"
    assert body["source"]["port_matching_type"] == "ANY"
    assert body["source"]["match_opposite_ports"] is False
    assert body["destination"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["port_matching_type"] == "ANY"
    assert body["destination"]["match_opposite_ports"] is False


def test_v2_create_wire_ip_target():
    body = policy_to_wire_v2_create(_np("New Rule", dst_ips=("1.2.3.4",)), V2_ZONES)
    assert body["source"]["matching_target"] == "ANY"
    assert body["source"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["matching_target"] == "IP"
    assert body["destination"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["ips"] == ["1.2.3.4"]
    assert body["destination"]["port_matching_type"] == "ANY"


def test_v2_create_wire_network_target():
    body = policy_to_wire_v2_create(
        _np("New Rule", src_networks=("APP",)), V2_ZONES, networks=V2_NETWORKS
    )
    assert body["source"]["matching_target"] == "NETWORK"
    assert body["source"]["matching_target_type"] == "SPECIFIC"
    assert body["source"]["network_ids"] == ["n-app"]
    assert body["destination"]["matching_target"] == "ANY"
    assert body["destination"]["matching_target_type"] == "SPECIFIC"


def test_v2_create_wire_port_matching_type_specific_when_ports_given():
    body = policy_to_wire_v2_create(_np("New Rule", dst_ports=("443",)), V2_ZONES)
    assert body["destination"]["port_matching_type"] == "SPECIFIC"
    assert body["source"]["port_matching_type"] == "ANY"


def test_v2_create_wire_network_takes_precedence_over_ips():
    # networks= wins over ips= for matching_target inference (networks= is more specific)
    body = policy_to_wire_v2_create(
        _np("New Rule", src_networks=("APP",), src_ips=("1.2.3.4",)),
        V2_ZONES, networks=V2_NETWORKS,
    )
    assert body["source"]["matching_target"] == "NETWORK"


# ---- policy_from_wire: new target types ---------------------------------- #

def test_policy_from_wire_reads_web_domains():
    p = policy_from_wire(RAW_WEB, {"Internal": "z-int", "External": "z-ext"})
    assert p.dst_web_domains == ("youtube.com", "youtu.be")
    assert p.dst_web_matching_type == "DOMAIN"
    assert p.src_web_domains == ()
    assert p.src_web_matching_type == ""


def test_policy_from_wire_reads_app_ids():
    p = policy_from_wire(RAW_APP, {"Internal": "z-int", "External": "z-ext"})
    assert p.dst_app_ids == ("app-yt", "app-fb")
    assert p.src_app_ids == ()


def test_policy_from_wire_reads_app_category_ids():
    p = policy_from_wire(RAW_APP_CAT, {"Internal": "z-int", "External": "z-ext"})
    assert p.dst_app_category_ids == ("cat-social",)
    assert p.src_app_category_ids == ()


def test_policy_from_wire_web_matching_type_empty_when_no_domains():
    p = policy_from_wire(RAW_CLIENT, {"Internal": "z-int", "External": "z-ext"})
    assert p.src_web_matching_type == ""
    assert p.dst_web_matching_type == ""


# ---- merge_desired_into_v2: web / app / app_category targets ------------- #

def test_merge_updates_web_domains():
    desired = _np("Block YT", dst_web_domains=("youtu.be",), dst_web_matching_type="DOMAIN")
    out = merge_desired_into_v2(RAW_WEB, desired, V2_ZONES_INT)
    assert out["destination"]["web_domains"] == ["youtu.be"]
    assert out["destination"]["web_matching_type"] == "DOMAIN"


def test_merge_clears_web_domains_when_desired_has_none():
    desired = _np("Block YT")
    out = merge_desired_into_v2(RAW_WEB, desired, V2_ZONES_INT)
    assert out["destination"]["web_domains"] == []
    assert out["destination"]["web_matching_type"] == "DOMAIN"


def test_merge_web_domain_type_mismatch_raises():
    desired = _np("x", dst_web_domains=("y.com",))
    with pytest.raises(APIError, match="not WEB"):
        merge_desired_into_v2(RAW_IP, desired, V2_ZONES_INT)


def test_merge_updates_app_ids():
    desired = _np("Block App", dst_app_ids=("app-yt",))
    out = merge_desired_into_v2(RAW_APP, desired, V2_ZONES_INT)
    assert out["destination"]["app_ids"] == ["app-yt"]


def test_merge_clears_app_ids_when_desired_has_none():
    desired = _np("Block App")
    out = merge_desired_into_v2(RAW_APP, desired, V2_ZONES_INT)
    assert out["destination"]["app_ids"] == []


def test_merge_app_type_mismatch_raises():
    desired = _np("x", dst_app_ids=("a1",))
    with pytest.raises(APIError, match="not APP"):
        merge_desired_into_v2(RAW_IP, desired, V2_ZONES_INT)


def test_merge_updates_app_category_ids():
    desired = _np("Block Cat", dst_app_category_ids=("cat-social",))
    out = merge_desired_into_v2(RAW_APP_CAT, desired, V2_ZONES_INT)
    assert out["destination"]["app_category_ids"] == ["cat-social"]


def test_merge_clears_app_category_ids_when_desired_has_none():
    desired = _np("Block Cat")
    out = merge_desired_into_v2(RAW_APP_CAT, desired, V2_ZONES_INT)
    assert out["destination"]["app_category_ids"] == []


# ---- v2 CREATE wire: new target types ------------------------------------ #

def test_v2_create_wire_app_target():
    body = policy_to_wire_v2_create(_np("Block Apps", dst_app_ids=("app-yt",)), V2_ZONES)
    assert body["destination"]["matching_target"] == "APP"
    assert body["destination"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["app_ids"] == ["app-yt"]
    assert "app_ids" not in body["source"]


def test_v2_create_wire_app_category_target():
    body = policy_to_wire_v2_create(
        _np("Block Cat", dst_app_category_ids=("cat-social",)), V2_ZONES
    )
    assert body["destination"]["matching_target"] == "APP_CATEGORY"
    assert body["destination"]["app_category_ids"] == ["cat-social"]


def test_v2_create_wire_web_domain_target():
    body = policy_to_wire_v2_create(
        _np("Block YT", dst_web_domains=("youtube.com",)), V2_ZONES
    )
    assert body["destination"]["matching_target"] == "WEB"
    assert body["destination"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["web_domains"] == ["youtube.com"]
    assert body["destination"]["web_matching_type"] == "DOMAIN"


def test_v2_create_wire_web_domain_explicit_matching_type():
    body = policy_to_wire_v2_create(
        _np("Block YT", dst_web_domains=("tube",), dst_web_matching_type="KEYWORD"),
        V2_ZONES,
    )
    assert body["destination"]["web_matching_type"] == "KEYWORD"


def test_v2_create_wire_network_priority_over_ips():
    # networks= wins over ips= — already tested, extended to cover full priority chain
    body = policy_to_wire_v2_create(
        _np("R", dst_app_ids=("a1",), dst_web_domains=("x.com",)), V2_ZONES
    )
    assert body["destination"]["matching_target"] == "APP"


def test_v2_create_wire_rejects_unknown_network():
    with pytest.raises(APIError, match="unknown network"):
        policy_to_wire_v2_create(
            _np("New Rule", src_networks=("NOPE",)), V2_ZONES, networks=V2_NETWORKS
        )


def test_v2_create_issues_post_and_returns_id():
    http = _FakeHTTP([
        _login_resp(),
        _Resp(body={"_id": "new-real-id"}),  # POST response
    ])
    client = UniFiClient(load(V2_ENV), http=http)
    returned_id = client.create_policy(_np("New Rule"), V2_ZONES)
    _, post_call = http.calls
    assert post_call.method == "POST"
    assert post_call.url.endswith("/firewall-policies")
    assert post_call.json["source"]["matching_target"] == "ANY"
    assert "description" not in post_call.json
    assert post_call.json["ip_version"] == "IPV4"
    assert post_call.json["connection_state_type"] == "CUSTOM"
    assert post_call.json["create_allow_respond"] is False
    assert post_call.json["source"]["port_matching_type"] == "ANY"
    assert returned_id == "new-real-id"


# ---- config: v2 credentials ---------------------------------------------- #
def test_config_loads_v2_credentials():
    cfg = load(V2_ENV)
    assert cfg.username == "admin" and cfg.password == "pw"
    assert cfg.site == "testsite"


def test_config_admin_zones_default_and_parse():
    assert load({"UDM_HOST": "1.2.3.4", "UDM_CA_FINGERPRINT": "ab"}).admin_zones == ("Internal",)
    cfg = load({**V2_ENV, "UNIFI_ADMIN_ZONES": "Internal, Vpn"})
    assert cfg.admin_zones == ("Internal", "Vpn")


def test_config_site_rejects_path_chars():
    with pytest.raises(ConfigError, match="UNIFI_SITE"):
        load({**V2_ENV, "UNIFI_SITE": "a/b/../c"})


def test_v2_client_without_credentials_raises():
    cfg = load({"UDM_HOST": "1.2.3.4", "UDM_CA_FINGERPRINT": "ab"})
    with pytest.raises(ConfigError, match="UNIFI_USERNAME"):
        UniFiClient(cfg, http=_FakeHTTP([]))


# ---- network membership (NETWORK-target rules) --------------------------- #
def test_from_wire_reads_network_ids_as_names():
    n = policy_from_wire(RAW_NETWORK, {"z-int": "Internal"}, V2_NETWORKS_BY_ID)
    assert n.src_networks == ("IOT", "iOS")
    assert n.dst_networks == ("APP",)


def test_from_wire_falls_back_to_id_when_map_missing():
    # no network map passed — the raw id survives rather than crashing
    n = policy_from_wire(RAW_NETWORK, {"z-int": "Internal"})
    assert "n-iot" in n.src_networks and "n-ios" in n.src_networks


def test_merge_writes_network_ids_for_network_target():
    V2_ZONES_INT = {"Internal": "z-int"}
    desired = _np("Block IOT to APP", src_zone="Internal", dst_zone="Internal",
                  src_networks=("IOT", "iOS"), dst_networks=("APP",))
    out = merge_desired_into_v2(RAW_NETWORK, desired, V2_ZONES_INT, V2_NETWORKS)
    assert out["source"]["network_ids"] == ["n-iot", "n-ios"]
    assert out["destination"]["network_ids"] == ["n-app"]
    assert out["source"]["matching_target"] == "NETWORK"  # untouched


def test_merge_rejects_networks_on_non_network_target():
    # YAML specifies networks but the live rule's source is CLIENT-type
    V2_ZONES_INT = {"Internal": "z-int", "External": "z-ext"}
    desired = _np("Mismatch", src_networks=("IOT",))
    with pytest.raises(APIError, match="matching_target"):
        merge_desired_into_v2(RAW_CLIENT, desired, V2_ZONES_INT, V2_NETWORKS)


def test_merge_rejects_unknown_network_name():
    V2_ZONES_INT = {"Internal": "z-int"}
    desired = _np("Bad", src_zone="Internal", dst_zone="Internal",
                  src_networks=("Nonexistent",))
    with pytest.raises(APIError, match="unknown network name"):
        merge_desired_into_v2(RAW_NETWORK, desired, V2_ZONES_INT, V2_NETWORKS)


def test_config_admin_networks_default_and_parse():
    assert load({"UDM_HOST": "1.2.3.4", "UDM_CA_FINGERPRINT": "ab"}).admin_networks == ("Default",)
    cfg = load({**V2_ENV, "UNIFI_ADMIN_NETWORKS": "Default, APP"})
    assert cfg.admin_networks == ("Default", "APP")


def test_client_http_exceptions_wrapped_in_apierror():
    # Test that connection exceptions in urllib3 are caught and wrapped in APIError.
    class FlakyHTTP:
        def request(self, *args, **kwargs):
            raise urllib3.exceptions.MaxRetryError(None, "http://host", "flaky network")
        def clear(self):
            pass
    client = UniFiClient(load(V2_ENV), http=FlakyHTTP())
    with pytest.raises(APIError, match="v2 login request failed:"):
        client.list_zones()


# ---- MAC address (CLIENT matching_target) --------------------------------- #

RAW_CLIENT_DST = {
    "_id": "pd", "name": "Block device", "enabled": True, "action": "BLOCK", "index": 7,
    "logging": False, "protocol": "all",
    "source": {"matching_target": "ANY", "port_matching_type": "ANY",
               "match_opposite_ports": False, "zone_id": "z-int"},
    "destination": {"matching_target": "CLIENT", "matching_target_type": "SPECIFIC",
                    "client_macs": ["11:22:33:44:55:66"], "port_matching_type": "ANY",
                    "match_opposite_ports": False, "zone_id": "z-ext"},
}

V2_ZONES_IE = {"Internal": "z-int", "External": "z-ext"}


def test_mac_validator_rejects_trailing_newline():
    from pydantic import ValidationError
    with pytest.raises((ValidationError, ValueError)):
        from unifi_reconciler.model import Endpoint
        Endpoint(zone="Internal", macs=["aa:bb:cc:dd:ee:ff\n"])


def test_policy_from_wire_normalizes_wire_macs_to_lowercase():
    raw = {"_id": "x", "name": "x", "action": "ALLOW", "index": 1,
           "source": {"zone_id": "z-lan", "client_macs": ["AA:BB:CC:DD:EE:FF"]},
           "destination": {"zone_id": "z-lan"}}
    p = policy_from_wire(raw, {"z-lan": "LAN"})
    assert p.src_macs == ("aa:bb:cc:dd:ee:ff",)


def test_policy_from_wire_reads_src_client_macs():
    p = policy_from_wire(RAW_CLIENT, {"z-old": "Internal", "z-old2": "External"})
    assert p.src_macs == ("aa:bb:cc:dd:ee:ff",)
    assert p.dst_macs == ()


def test_policy_from_wire_reads_dst_client_macs():
    p = policy_from_wire(RAW_CLIENT_DST, {"z-int": "Internal", "z-ext": "External"})
    assert p.dst_macs == ("11:22:33:44:55:66",)
    assert p.src_macs == ()


def test_policy_from_wire_empty_macs_when_absent():
    raw = {"_id": "x", "name": "x", "action": "ALLOW", "index": 1,
           "source": {"zone_id": "z-lan"}, "destination": {"zone_id": "z-lan"}}
    p = policy_from_wire(raw, {"z-lan": "LAN"})
    assert p.src_macs == () and p.dst_macs == ()


def test_v2_create_wire_client_target_src():
    body = policy_to_wire_v2_create(
        _np("Kids online", src_macs=("aa:bb:cc:dd:ee:ff",)), V2_ZONES
    )
    assert body["source"]["matching_target"] == "CLIENT"
    assert body["source"]["matching_target_type"] == "SPECIFIC"
    assert body["source"]["client_macs"] == ["aa:bb:cc:dd:ee:ff"]
    assert body["destination"]["matching_target"] == "ANY"
    assert "client_macs" not in body["destination"]


def test_v2_create_wire_client_target_dst():
    body = policy_to_wire_v2_create(
        _np("Block device", dst_macs=("11:22:33:44:55:66",)), V2_ZONES
    )
    assert body["destination"]["matching_target"] == "CLIENT"
    assert body["destination"]["matching_target_type"] == "SPECIFIC"
    assert body["destination"]["client_macs"] == ["11:22:33:44:55:66"]
    assert body["source"]["matching_target"] == "ANY"


def test_v2_create_wire_client_rejects_macs_and_ips_combined():
    # macs + ips on the same side is rejected — the combination is ambiguous and
    # previously caused silent IP suppression (F3 / differential review 2026-06-09)
    with pytest.raises(APIError, match="both macs and ips"):
        policy_to_wire_v2_create(
            _np("R", src_macs=("aa:bb:cc:dd:ee:ff",), src_ips=("1.2.3.4",)), V2_ZONES
        )


def test_merge_updates_client_macs():
    desired = _np("Kids Allowed", src_macs=("de:ad:be:ef:00:01",))
    out = merge_desired_into_v2(RAW_CLIENT, desired, V2_ZONES_IE)
    assert out["source"]["client_macs"] == ["de:ad:be:ef:00:01"]
    assert out["source"]["matching_target"] == "CLIENT"  # preserved verbatim


def test_merge_preserves_client_macs_when_desired_has_none():
    # Empty src_macs in the desired YAML must NOT zero out the live client_macs list.
    desired = _np("Kids Allowed")  # no macs specified
    out = merge_desired_into_v2(RAW_CLIENT, desired, V2_ZONES_IE)
    assert out["source"]["client_macs"] == ["aa:bb:cc:dd:ee:ff"]


def test_merge_macs_type_mismatch_raises():
    # Desired carries macs but the live rule's source is not CLIENT-target.
    desired = _np("Allow parent", src_macs=("aa:bb:cc:dd:ee:ff",))
    with pytest.raises(APIError, match="not CLIENT"):
        merge_desired_into_v2(RAW_IP, desired, V2_ZONES_IE)


def test_v2_create_issues_post_with_client_macs():
    http = _FakeHTTP([
        _login_resp(),
        _Resp(body={"_id": "new-mac-rule"}),
    ])
    client = UniFiClient(load(V2_ENV), http=http)
    rule_id = client.create_policy(
        _np("Kids online", src_macs=("aa:bb:cc:dd:ee:ff",)), V2_ZONES
    )
    _, post_call = http.calls
    assert post_call.method == "POST"
    assert post_call.json["source"]["matching_target"] == "CLIENT"
    assert post_call.json["source"]["client_macs"] == ["aa:bb:cc:dd:ee:ff"]
    assert post_call.json["destination"]["matching_target"] == "ANY"
    assert rule_id == "new-mac-rule"


def test_v2_update_overlays_client_macs():
    http = _FakeHTTP([
        _login_resp(),
        _Resp(body=RAW_CLIENT),         # GET-by-id
        _Resp(body={"_id": "p1"}),      # PUT
    ])
    client = UniFiClient(load(V2_ENV), http=http)
    client.update_policy("p1", _np("Kids Allowed", src_macs=("de:ad:be:ef:00:01",)), V2_ZONES)
    _, _, put_call = http.calls
    assert put_call.json["source"]["client_macs"] == ["de:ad:be:ef:00:01"]
