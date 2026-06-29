"""UniFi v2 API client — the single place that knows the wire format.

Everything uncertain about the UDM API surface is contained here on purpose: the
endpoint paths and the JSON field mapping. The rest of the package (loader, diff,
safety, reconcile) is wire-neutral and fully unit-tested against the
:class:`PolicyStore` protocol with a fake, so correcting a field name here never
ripples outward.

This targets the internal **v2** surface (``/proxy/network/v2/api``, cookie+CSRF
login). It is the only surface that exposes firewall policies with a stable
per-rule ``_id`` on current controllers — the official Integration API returns
``401`` for firewall policies.

VERIFY-ON-FIRST-RUN
-------------------
The v2 firewall schema keeps expanding release-to-release. If a field name is off
on your controller, ``unifi-reconciler introspect`` dumps one raw live policy so
you can eyeball the real shape; the fix is almost always a one-line edit here.
"""

from __future__ import annotations

import copy
import hashlib
import re
import ssl
from typing import Any, Protocol
from urllib.parse import quote

import urllib3

from .config import Config, ConfigError
from .model import Action, ConnectionStateType, IpVersion, Protocol as Proto
from .networks import Network, build_network_map
from .normalized import NormalizedPolicy

# --------------------------------------------------------------------------- #
# Endpoint catalogue — centralized so a path change is a one-line edit.
# --------------------------------------------------------------------------- #
_ENDPOINTS = {
    # zones live at .../firewall/zone (singular) on v2; the plural 404s.
    # Verified live: returns 6 zone objects keyed by _id/name, each carrying a
    # network_ids[] membership list.
    "zones": "/proxy/network/v2/api/site/{site}/firewall/zone",
    "policies": "/proxy/network/v2/api/site/{site}/firewall-policies",
    "policy": "/proxy/network/v2/api/site/{site}/firewall-policies/{id}",
    # L3 network configs. The v2 surface 404s for this; the classic
    # /api/s/{site}/rest/networkconf path works with the same cookie+CSRF
    # session. Read-only context (zone membership is on the zone side).
    "networks": "/proxy/network/api/s/{site}/rest/networkconf",
}


class SecurityError(RuntimeError):
    """Raised when the TLS pin does not match — a hard stop, never bypassed."""


class APIError(RuntimeError):
    pass


class PolicyStore(Protocol):
    """The surface the reconciler depends on. The real client and the test fake
    both implement this; nothing downstream touches requests or JSON directly."""

    def list_zones(self) -> dict[str, str]:
        """Return {zone_name: zone_id} for the site."""

    def list_policies(self) -> list[NormalizedPolicy]:
        """Return ALL live policies (managed + unmanaged), normalized, with ids."""

    def create_policy(self, desired: NormalizedPolicy, zones: dict[str, str]) -> str:
        ...

    def update_policy(
        self, policy_id: str, desired: NormalizedPolicy, zones: dict[str, str]
    ) -> None:
        ...

    def delete_policy(self, policy_id: str) -> None:
        ...


# --------------------------------------------------------------------------- #
# TLS pinning
# --------------------------------------------------------------------------- #
# The UDM serves a self-signed *leaf* cert (CN=unifi.local) with basicConstraints
# CA:FALSE, so it cannot be used as an OpenSSL trust anchor ("invalid CA
# certificate"). Instead we pin by certificate fingerprint: urllib3's
# assert_fingerprint hashes the peer cert presented on the *actual* data
# connection and rejects any mismatch — proper pinning, no CA semantics, no
# hostname/SAN dependence.
def leaf_fingerprint(host: str, port: int = 443) -> tuple[str, str]:
    """Return (sha256_hex, pem) of the server's leaf certificate."""
    pem = ssl.get_server_certificate((host, port))
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest(), pem


def build_pool(
    cfg: Config, *, headers: dict[str, str] | None = None
) -> urllib3.PoolManager:
    """Build a urllib3 PoolManager whose TLS is pinned to the configured cert
    fingerprint (or, in insecure capture mode, prints the live fingerprint and
    pins nothing). assert_fingerprint enforces the pin on the real connection.

    ``headers`` are baked into the pool as defaults; auth itself is the per-request
    cookie+CSRF session established by :meth:`UniFiClient._v2_login`."""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if headers is None:
        headers = {"Accept": "application/json"}
    retries = urllib3.util.Retry(
        total=3,
        connect=3,
        read=2,
        status=3,
        status_forcelist={500, 502, 503, 504},
        backoff_factor=1.0,
        allowed_methods={"GET", "POST", "PUT", "DELETE"},
        raise_on_status=True,
    )
    common: dict[str, Any] = {
        "cert_reqs": "CERT_NONE",   # chain verification off; the fingerprint IS the check
        "assert_hostname": False,   # IP-addressed self-signed leaf has no usable SAN
        "headers": headers,
        "timeout": urllib3.Timeout(connect=cfg.timeout, read=cfg.timeout),
        "retries": retries,
    }
    if cfg.ca_fingerprint:
        return urllib3.PoolManager(assert_fingerprint=cfg.ca_fingerprint, **common)
    if cfg.insecure_tls:
        # config.load enforced pin-or-insecure; this branch is fingerprint capture.
        actual, _ = leaf_fingerprint(cfg.host)
        print(f"[unifi-reconciler] UDM leaf SHA-256 fingerprint: {actual}")
        print("[unifi-reconciler] pin this via UDM_CA_FINGERPRINT and drop UNIFI_INSECURE_TLS")
        return urllib3.PoolManager(**common)
    raise SecurityError("no TLS pin configured and insecure mode not set")  # pragma: no cover


# --------------------------------------------------------------------------- #
# Field mapping (wire <-> normalized) — the only place that knows JSON keys.
# --------------------------------------------------------------------------- #
_ACTION_TO_WIRE = {Action.ALLOW: "ALLOW", Action.BLOCK: "BLOCK", Action.REJECT: "REJECT"}
_WIRE_TO_ACTION = {v: k for k, v in _ACTION_TO_WIRE.items()}
_WIRE_TO_CST: dict[str, ConnectionStateType] = {
    "ALL": ConnectionStateType.ALL,
    "RESPOND_ONLY": ConnectionStateType.RESPOND_ONLY,
    "CUSTOM": ConnectionStateType.CUSTOM,
}
_WIRE_TO_IPV: dict[str, IpVersion] = {
    "IPV4": IpVersion.IPV4,
    "IPV6": IpVersion.IPV6,
    "BOTH": IpVersion.BOTH,
}
_PROTO_TO_WIRE = {
    Proto.ALL: "all",
    Proto.TCP: "tcp",
    Proto.UDP: "udp",
    Proto.TCP_UDP: "tcp_udp",
    Proto.ICMP: "icmp",
}
_WIRE_TO_PROTO = {v: k for k, v in _PROTO_TO_WIRE.items()}


def build_path(template: str, **params: Any) -> str:
    """Fill an endpoint template, URL-encoding every interpolated segment so a
    stray '/', '?' or '..' in a value cannot retarget the request."""
    safe = {k: quote(str(v), safe="") for k, v in params.items()}
    return template.format(**safe)


def _zone_name(zones_by_id: dict[str, str], zone_id: Any) -> str:
    return zones_by_id.get(str(zone_id), str(zone_id))


def _net_name(networks_by_id: dict[str, str], net_id: str) -> str:
    # Falls back to the raw id when the map is absent or the network was deleted
    # between the fetch and parse. A missing mapping produces a
    # perpetual spurious diff (live names won't match YAML names) but never a bad
    # write — the update path re-fetches networks_by_name before writing network_ids.
    return networks_by_id.get(net_id, net_id)


def _read_ports(side: dict) -> tuple[str, ...]:
    """Read ports from a v2 endpoint dict.

    The v2 wire format uses ``ports`` (array of strings/ranges) for most rules
    and ``port`` (scalar) for single-port rules on older firmware. Both are
    normalised to a tuple of strings so the rest of the pipeline sees one shape.
    """
    ps = side.get("ports") or []
    if not ps:
        p = side.get("port")
        if p is not None:
            ps = [p]
    return tuple(str(x) for x in ps)


def policy_from_wire(
    raw: dict,
    zones_by_id: dict[str, str],
    networks_by_id: dict[str, str] | None = None,
) -> NormalizedPolicy:
    """Project a raw API policy object onto NormalizedPolicy. Tolerant of missing
    optional keys so an unfamiliar field never crashes a read-only plan."""
    src = raw.get("source", {}) or {}
    dst = raw.get("destination", {}) or {}
    nb = networks_by_id or {}
    return NormalizedPolicy(
        name=raw.get("name", ""),
        enabled=bool(raw.get("enabled", True)),
        action=_WIRE_TO_ACTION.get(str(raw.get("action", "")).upper(), Action.BLOCK),
        index=int(raw.get("index", raw.get("rule_index", 0)) or 0),
        src_zone=_zone_name(zones_by_id, src.get("zone_id", src.get("zone", ""))),
        dst_zone=_zone_name(zones_by_id, dst.get("zone_id", dst.get("zone", ""))),
        protocol=_WIRE_TO_PROTO.get(str(raw.get("protocol", "all")).lower(), Proto.ALL),
        logging=bool(raw.get("logging", False)),
        description=raw.get("description", "") or "",
        src_ips=tuple(src.get("ips", []) or []),
        src_ports=_read_ports(src),
        src_networks=tuple(_net_name(nb, nid) for nid in (src.get("network_ids") or [])),
        src_web_domains=tuple(src.get("web_domains") or []),
        src_web_matching_type=(src.get("web_matching_type") or "") if src.get("web_domains") else "",
        src_app_ids=tuple(str(x) for x in (src.get("app_ids") or [])),
        src_app_category_ids=tuple(str(x) for x in (src.get("app_category_ids") or [])),
        src_macs=tuple(m.lower() for m in (src.get("client_macs") or [])),
        dst_ips=tuple(dst.get("ips", []) or []),
        dst_ports=_read_ports(dst),
        dst_networks=tuple(_net_name(nb, nid) for nid in (dst.get("network_ids") or [])),
        dst_web_domains=tuple(dst.get("web_domains") or []),
        dst_web_matching_type=(dst.get("web_matching_type") or "") if dst.get("web_domains") else "",
        dst_app_ids=tuple(str(x) for x in (dst.get("app_ids") or [])),
        dst_app_category_ids=tuple(str(x) for x in (dst.get("app_category_ids") or [])),
        dst_macs=tuple(m.lower() for m in (dst.get("client_macs") or [])),
        # The v2 surface returns the id as "_id"; tolerate "id" too for forward-compat.
        policy_id=(str(raw["_id"]) if raw.get("_id") is not None
                   else str(raw["id"]) if raw.get("id") is not None else None),
        predefined=bool(raw.get("predefined", raw.get("system", False))),
        connection_state_type=_WIRE_TO_CST.get(raw.get("connection_state_type", ""), ConnectionStateType.CUSTOM),
        connection_states=tuple(raw.get("connection_states") or []),
        ip_version=_WIRE_TO_IPV.get(raw.get("ip_version", ""), IpVersion.IPV4),
        auto_return_traffic=bool(raw.get("create_allow_respond", False)),
    )


def _infer_matching_target(
    ips: tuple, networks: tuple,
    app_ids: tuple = (), app_cat_ids: tuple = (), web_domains: tuple = (),
    macs: tuple = (),
) -> str:
    if macs:
        return "CLIENT"
    if networks:
        return "NETWORK"
    if ips:
        return "IP"
    if app_ids:
        return "APP"
    if app_cat_ids:
        return "APP_CATEGORY"
    if web_domains:
        return "WEB"
    return "ANY"


def policy_to_wire_v2_create(
    p: NormalizedPolicy, zones: dict[str, str], networks: dict[str, str] | None = None
) -> dict:
    """POST body for a v2 *create* (``POST /proxy/network/v2/api/site/{site}/firewall-policies``).

    The v2 bean validator requires every field listed below even when the
    declarative model has no opinion on them. Omitting any one causes a 400.
    These defaults were discovered empirically against Network Application
    v9.x (UDM SE, firmware 4.x) on 2026-06-09:

    Top-level required fields
    -------------------------
    ``ip_version``
        Must be present. ``"IPV4"`` for all rules this reconciler creates
        (the model is IPv4-only).

    ``connection_state_type``
        Enum: ``ALL`` | ``RESPOND_ONLY`` | ``CUSTOM``. Must be ``"CUSTOM"``
        for creates — the controller rejects ``"ALL"`` and ``"RESPOND_ONLY"``
        with *"Firewall policy create respond traffic not allowed"* because
        both include respond/established states (stateful return traffic is
        managed by the controller's predefined rules, not user-created ones).

    ``connection_states``
        Required when ``connection_state_type`` is ``"CUSTOM"``. ``["NEW"]``
        matches new connection attempts only; stateful inspection covers
        the return direction automatically.

    ``create_allow_respond``
        Boolean flag the controller uses to decide whether a CREATE is
        building a respond/established-traffic rule. Must be ``False`` for
        user-created rules — omitting it causes the controller to default to
        ``True``, triggering *"Firewall policy create respond traffic not
        allowed"* even when ``connection_state_type`` is ``"CUSTOM"``.

    ``match_opposite_protocol``
        Required boolean; ``False`` is the safe default.

    ``schedule``
        Required object; ``{"mode": "ALWAYS"}`` means no time restriction.

    Per-side required fields (``source`` / ``destination``)
    -------------------------------------------------------
    ``matching_target_type``
        Required alongside ``matching_target``. Controller enum is
        ``[SPECIFIC, OBJECT]`` — ``"ANY"`` is **not** a valid value even
        when ``matching_target`` itself is ``"ANY"``. Always ``"SPECIFIC"``
        for direct matches (IPs, ports, networks, MACs, apps); ``"OBJECT"``
        is for named group references which this reconciler never creates.
        Omitting it produces *"Missing firewall destination matching target
        type"*.

    ``port_matching_type``
        Required. ``"SPECIFIC"`` when ports are provided, ``"ANY"``
        otherwise.

    ``match_opposite_ports``
        Required boolean alongside ``port_matching_type``; ``False`` is
        the safe default.

    v2 has no ``description`` field — deliberately omitted from the body.
    ``matching_target`` is inferred from the endpoint fields (priority:
    NETWORK > IP > APP > APP_CATEGORY > WEB > ANY).
    """
    for zone in (p.src_zone, p.dst_zone):
        if zone not in zones:
            raise APIError(
                f"policy {p.name!r} references unknown zone {zone!r}; "
                f"known zones: {sorted(zones)}"
            )
    nb = networks or {}

    def _side(
        zone: str, ips: tuple, ports: tuple, nets: tuple,
        app_ids: tuple, app_cat_ids: tuple, web_domains: tuple, web_mt: str,
        macs: tuple = (),
    ) -> dict:
        matching_target = _infer_matching_target(ips, nets, app_ids, app_cat_ids, web_domains, macs)
        side: dict = {
            "zone_id": zones[zone],
            "matching_target": matching_target,
            # Controller enum is [SPECIFIC, OBJECT] — "ANY" is not a valid value even
            # when matching_target itself is "ANY". Use SPECIFIC for all direct matches
            # (IPs, ports, networks, MACs, apps); OBJECT is for named IP/port group refs
            # which this reconciler never creates.
            "matching_target_type": "SPECIFIC",
            "port_matching_type": "SPECIFIC" if ports else "ANY",
            "match_opposite_ports": False,
        }
        if macs:
            if ips:
                raise APIError(
                    f"policy {p.name!r}: {zone!r} side specifies both macs and ips — "
                    "CLIENT matching_target does not support IP refinement; "
                    "remove ips: or macs: from this endpoint."
                )
            side["client_macs"] = list(macs)
        if ips and matching_target != "CLIENT":
            side["ips"] = list(ips)
        if ports:
            side["port"] = ports[0]
        if nets:
            missing = [n for n in nets if n not in nb]
            if missing:
                raise APIError(
                    f"policy {p.name!r}: references unknown network name(s) "
                    f"{missing!r}; known networks: {sorted(nb)}"
                )
            side["network_ids"] = [nb[n] for n in nets]
        if app_ids:
            side["app_ids"] = list(app_ids)
        if app_cat_ids:
            side["app_category_ids"] = list(app_cat_ids)
        if web_domains:
            side["web_domains"] = list(web_domains)
            side["web_matching_type"] = web_mt or "DOMAIN"
        return side

    _cst = (p.connection_state_type or ConnectionStateType.CUSTOM)
    _css = (
        list(p.connection_states) if p.connection_states
        else ([] if _cst != ConnectionStateType.CUSTOM else ["NEW"])
    )
    return {
        "name": p.name,
        "enabled": p.enabled,
        "action": _ACTION_TO_WIRE[p.action],
        "index": p.index,
        "protocol": _PROTO_TO_WIRE[p.protocol],
        "logging": p.logging,
        "ip_version": (p.ip_version or IpVersion.IPV4).value,
        "connection_state_type": _cst.value,
        "connection_states": _css,
        "create_allow_respond": p.auto_return_traffic if p.auto_return_traffic is not None else False,
        "match_opposite_protocol": False,
        "schedule": {"mode": "ALWAYS"},
        "source": _side(
            p.src_zone, p.src_ips, p.src_ports, p.src_networks,
            p.src_app_ids, p.src_app_category_ids, p.src_web_domains, p.src_web_matching_type,
            p.src_macs,
        ),
        "destination": _side(
            p.dst_zone, p.dst_ips, p.dst_ports, p.dst_networks,
            p.dst_app_ids, p.dst_app_category_ids, p.dst_web_domains, p.dst_web_matching_type,
            p.dst_macs,
        ),
    }


def merge_desired_into_v2(
    raw: dict,
    p: NormalizedPolicy,
    zones: dict[str, str],
    networks: dict[str, str] | None = None,
) -> dict:
    """Read-modify-write body for a v2 *update*: overlay only the modeled fields
    onto a copy of the live raw policy, preserving the ``matching_target`` union
    and every v2-only field (``schedule``, ``connection_states``, ``ip_version``,
    ``client_macs``/``web_domains``/``network_ids``/``app_ids``, the match flags…).

    The v2 source/destination is a 7-way union the declarative model cannot
    represent, so synthesizing a full body would strip whatever we don't model.
    Instead we touch only the fields the model owns and leave the rest verbatim.

    ``networks`` is the {name: network_id} map; required only when a side carries
    ``src_networks``/``dst_networks``. An unknown name or a type mismatch (networks
    on a non-NETWORK side) is refused rather than silently ignored."""
    for zone in (p.src_zone, p.dst_zone):
        if zone not in zones:
            raise APIError(
                f"policy {p.name!r} references unknown zone {zone!r}; "
                f"known zones: {sorted(zones)}"
            )
    body = copy.deepcopy(raw)
    body["name"] = p.name
    body["enabled"] = p.enabled
    body["action"] = _ACTION_TO_WIRE[p.action]
    body["index"] = p.index
    body["logging"] = p.logging
    body["protocol"] = _PROTO_TO_WIRE[p.protocol]
    body.pop("description", None)  # v2 has no description field; never introduce one
    for side, zone, ips, ports, side_networks, app_ids, app_cat_ids, web_domains, web_mt, macs in (
        ("source",
         p.src_zone, p.src_ips, p.src_ports, p.src_networks,
         p.src_app_ids, p.src_app_category_ids, p.src_web_domains, p.src_web_matching_type,
         p.src_macs),
        ("destination",
         p.dst_zone, p.dst_ips, p.dst_ports, p.dst_networks,
         p.dst_app_ids, p.dst_app_category_ids, p.dst_web_domains, p.dst_web_matching_type,
         p.dst_macs),
    ):
        sd = body.get(side)
        if not isinstance(sd, dict):
            sd = body[side] = {}
        sd["zone_id"] = zones[zone]
        mt = sd.get("matching_target")
        # Only IP-target sides carry a modeled `ips` list; for CLIENT/APP/APP_CATEGORY/
        # WEB/NETWORK/ANY the matching specifics are handled per-type below.
        if mt == "IP":
            sd["ips"] = list(ips)
        # Ports apply to any matching-target type. Always write the model's
        # ports so that adding/removing ports in the YAML is applied correctly.
        # IP-target rules use the scalar "port" field; all others use "ports" (array).
        if ports:
            sd["port"] = ports[0]
            sd.pop("ports", None)
            sd["port_matching_type"] = "SPECIFIC"
            sd["match_opposite_ports"] = False
        else:
            sd.pop("ports", None)
            sd.pop("port", None)
            sd["port_matching_type"] = "ANY"
        if side_networks:
            if mt != "NETWORK":
                raise APIError(
                    f"policy {p.name!r}: {side} specifies networks={list(side_networks)!r} "
                    f"but the live rule's matching_target is {mt!r} (not NETWORK) — "
                    "the refinement cannot be applied. Fix the YAML or the live rule type."
                )
            nb = networks or {}
            missing = [n for n in side_networks if n not in nb]
            if missing:
                raise APIError(
                    f"policy {p.name!r}: {side} references unknown network name(s) "
                    f"{missing!r}; known networks: {sorted(nb)}"
                )
            sd["network_ids"] = [nb[n] for n in side_networks]
        if app_ids or mt == "APP":
            if app_ids and mt != "APP":
                raise APIError(
                    f"policy {p.name!r}: {side} specifies app_ids={list(app_ids)!r} "
                    f"but the live rule's matching_target is {mt!r} (not APP)."
                )
            sd["app_ids"] = list(app_ids)
        if app_cat_ids or mt == "APP_CATEGORY":
            if app_cat_ids and mt != "APP_CATEGORY":
                raise APIError(
                    f"policy {p.name!r}: {side} specifies app_category_ids={list(app_cat_ids)!r} "
                    f"but the live rule's matching_target is {mt!r} (not APP_CATEGORY)."
                )
            sd["app_category_ids"] = list(app_cat_ids)
        if web_domains or mt == "WEB":
            if web_domains and mt != "WEB":
                raise APIError(
                    f"policy {p.name!r}: {side} specifies web_domains={list(web_domains)!r} "
                    f"but the live rule's matching_target is {mt!r} (not WEB)."
                )
            sd["web_domains"] = list(web_domains)
            sd["web_matching_type"] = web_mt or "DOMAIN"
        if macs:
            # Only overlay when explicitly provided; empty means "preserve live client_macs"
            # so that a YAML rule without macs: [...] doesn't silently clear an existing
            # CLIENT-target rule's MAC list on every reconcile pass.
            if mt != "CLIENT":
                raise APIError(
                    f"policy {p.name!r}: {side} specifies macs={list(macs)!r} "
                    f"but the live rule's matching_target is {mt!r} (not CLIENT)."
                )
            sd["client_macs"] = list(macs)
    # Only overlay these fields when explicitly set in the YAML (not None).
    # None means "preserve whatever the live rule has."
    if p.connection_state_type is not None:
        body["connection_state_type"] = p.connection_state_type.value
        if p.connection_state_type == ConnectionStateType.CUSTOM:
            body["connection_states"] = list(p.connection_states) if p.connection_states else ["NEW"]
        else:
            body.pop("connection_states", None)
    if p.ip_version is not None:
        body["ip_version"] = p.ip_version.value
    if p.auto_return_traffic is not None:
        body["create_allow_respond"] = p.auto_return_traffic
    return body


# --------------------------------------------------------------------------- #
# v2 session auth helpers
# --------------------------------------------------------------------------- #
def _parse_token_cookie(set_cookie: str) -> str:
    """Pull the TOKEN value out of a (possibly multi-cookie) Set-Cookie header.

    urllib3 joins multiple Set-Cookie headers with ', ', and session cookies
    carry commas in their Expires date, so we locate the TOKEN= marker directly
    instead of splitting on commas."""
    marker = "TOKEN="
    idx = set_cookie.find(marker)
    if idx == -1:
        return ""
    return set_cookie[idx + len(marker):].split(";", 1)[0]


# --------------------------------------------------------------------------- #
# Concrete client
# --------------------------------------------------------------------------- #
class UniFiClient:
    def __init__(self, cfg: Config, *, http: Any = None):
        self._cfg = cfg
        # v2 addresses the site by its internal shortname (usually "default").
        self._site = cfg.site
        # v2 cookie+CSRF session state; populated lazily by _ensure_session().
        self._token: str | None = None
        self._csrf: str | None = None
        # network list cached after first fetch (None = not yet fetched).
        self._networks_cache: list[Network] | None = None
        if not (cfg.username and cfg.password):
            raise ConfigError(
                "UNIFI_USERNAME and UNIFI_PASSWORD are required: the v2 API logs in "
                "for a cookie+CSRF session."
            )
        # Injected transport (tests) or the cookie+CSRF session pool.
        self._http = http if http is not None else build_pool(cfg)

    def close(self) -> None:
        self._http.clear()

    def __enter__(self) -> "UniFiClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _path(self, key: str, **kw: str) -> str:
        # site is operator-config (also validated at load); ids come from UDM
        # responses. build_path URL-encodes both as defense-in-depth.
        return build_path(_ENDPOINTS[key], site=self._site, **kw)

    # ----- v2 cookie+CSRF session ------------------------------------------ #
    def _ensure_session(self) -> None:
        """Log in once, lazily, on the first request of the session."""
        if self._token is None:
            self._v2_login()

    def _v2_login(self) -> None:
        cfg = self._cfg
        try:
            resp = self._http.request(
                "POST",
                cfg.base_url + "/api/auth/login",
                json={"username": cfg.username, "password": cfg.password, "rememberMe": True},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except urllib3.exceptions.HTTPError as exc:
            raise APIError(f"v2 login request failed: {exc}") from exc
        if resp.status != 200:
            raise APIError(
                f"v2 login -> {resp.status} {resp.reason}{self._error_detail(resp)}"
            )
        token = _parse_token_cookie(resp.headers.get("Set-Cookie", "") or "")
        if not token:
            raise APIError("v2 login succeeded but returned no TOKEN cookie")
        self._token = token
        # CSRF is required on mutating calls and rotates on every response.
        self._csrf = (resp.headers.get("X-Updated-CSRF-Token")
                      or resp.headers.get("X-CSRF-Token") or "")

    def _auth_headers(self) -> dict[str, str]:
        """Per-request headers: the session cookie plus the current CSRF token."""
        headers = {"Accept": "application/json", "Cookie": f"TOKEN={self._token}"}
        if self._csrf:
            headers["X-CSRF-Token"] = self._csrf
        return headers

    @staticmethod
    def _error_detail(resp: Any) -> str:
        """Extract structured error info from an error body.

        For Spring bean-validation 400s the interesting content is spread across
        the ``message`` field (which names the failing field) and the ``errors``
        array (which gives the constraint message). Both are extracted so the
        full field path is visible in the APIError without dumping the raw body."""
        try:
            data = resp.json()
        except Exception:
            return ""
        if not isinstance(data, dict):
            return ""
        parts: list[str] = []
        for key in ("message", "msg", "error"):
            val = data.get(key)
            if isinstance(val, str) and val:
                parts.append(val[:400])
                break
        meta = data.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("msg"), str):
            parts.append(meta["msg"][:400])
        # Spring MethodArgumentNotValidException includes an ``errors`` list of
        # per-field constraint violations — surface the first one.
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            e = errors[0]
            if isinstance(e, dict):
                field = (e.get("field") or e.get("objectName") or "")[:120]
                msg = (e.get("defaultMessage") or e.get("message") or "")[:160]
                rejected = repr(e.get("rejectedValue"))[:120]
                parts.append(f"field={field!r} rejected={rejected} msg={msg!r}")
        return (": " + " | ".join(parts)) if parts else ""

    def _request(self, method: str, path: str, *, json: Any = None) -> Any:
        self._ensure_session()
        try:
            resp = self._http.request(
                method, self._cfg.base_url + path, json=json, headers=self._auth_headers()
            )
        except urllib3.exceptions.HTTPError as exc:
            raise APIError(f"{method} {path} request failed: {exc}") from exc
        # The v2 CSRF token rotates on every response; carry the latest forward
        # or the next mutating call gets a 403.
        rotated = resp.headers.get("X-Updated-CSRF-Token")
        if rotated:
            self._csrf = rotated
        if resp.status >= 400:
            raise APIError(
                f"{method} {path} -> {resp.status} "
                f"{resp.reason}{self._error_detail(resp)}"
            )
        if resp.status == 204 or not resp.data:
            return None
        payload = resp.json()
        # Some endpoints wrap list results in {"data": [...]}; tolerate both shapes.
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def _raw_policy(self, policy_id: str) -> dict:
        """Fetch one live policy by id as its raw wire dict (for read-modify-write).

        Fails closed if the fetch comes back empty or without a matching id: a
        read-modify-write PUT must overlay onto the *real* live object, never a
        body reconstructed from nothing (which would strip the matching_target
        union and silently neuter the rule)."""
        data = self._request("GET", self._path("policy", id=policy_id))
        if isinstance(data, list):
            data = data[0] if data else {}
        wire_id = data.get("_id") or data.get("id") if isinstance(data, dict) else None
        if not wire_id:
            raise APIError(
                f"read-modify-write: could not fetch live policy {policy_id!r} "
                "(empty response) — refusing to update without its current state"
            )
        return data

    def _cached_networks(self) -> list[Network]:
        """Fetch and cache the network list for this session (v2 only)."""
        if self._networks_cache is None:
            self._networks_cache = self.list_networks()
        return self._networks_cache

    def _networks_by_id(self) -> dict[str, str]:
        """Return {network_id: name}."""
        return {n.network_id: n.name for n in self._cached_networks()}

    def _networks_by_name(self) -> dict[str, str]:
        """Return {name: network_id}."""
        return {n.name: n.network_id for n in self._cached_networks()}

    # ----- PolicyStore implementation -------------------------------------- #
    def list_zones(self) -> dict[str, str]:
        data = self._request("GET", self._path("zones")) or []
        out: dict[str, str] = {}
        for z in data:
            name, zid = z.get("name"), (z.get("id") or z.get("_id"))
            if name and zid:
                out[name] = str(zid)
        return out

    def list_policies(self) -> list[NormalizedPolicy]:
        zones_by_id = {v: k for k, v in self.list_zones().items()}
        data = self._request("GET", self._path("policies")) or []
        # Only resolve network ids if at least one live policy carries network_ids —
        # avoids an extra round-trip on controllers that have no NETWORK-type rules.
        has_network_sides = any(
            (r.get("source", {}) or {}).get("network_ids")
            or (r.get("destination", {}) or {}).get("network_ids")
            for r in data
        )
        nb = self._networks_by_id() if has_network_sides else {}
        return [policy_from_wire(raw, zones_by_id, nb) for raw in data]

    def create_policy(self, desired: NormalizedPolicy, zones: dict[str, str]) -> str:
        networks = (self._networks_by_name()
                    if (desired.src_networks or desired.dst_networks) else None)
        body = policy_to_wire_v2_create(desired, zones, networks)
        created = self._request("POST", self._path("policies"), json=body) or {}
        uid = str(created.get("_id") or created.get("id") or "")
        if uid and not re.fullmatch(r"[A-Za-z0-9_-]+", uid):
            raise APIError(
                f"controller returned unsafe policy id for {desired.name!r}: {uid!r}"
            )
        return uid

    def update_policy(
        self, policy_id: str, desired: NormalizedPolicy, zones: dict[str, str]
    ) -> None:
        # Read-modify-write: overlay modeled fields onto the live raw policy so
        # the matching_target union and all v2-only fields survive.
        networks = (self._networks_by_name()
                    if (desired.src_networks or desired.dst_networks) else {})
        merged = merge_desired_into_v2(
            self._raw_policy(policy_id), desired, zones, networks
        )
        self._request("PUT", self._path("policy", id=policy_id), json=merged)

    def delete_policy(self, policy_id: str) -> None:
        self._request("DELETE", self._path("policy", id=policy_id))

    def raw_policies(self) -> Any:
        """Unmapped dump for `unifi-reconciler introspect` — schema verification aid."""
        return self._request("GET", self._path("policies"))

    # ----- read-only network introspection (context, not reconciled) ------- #
    def raw_zones(self) -> list[dict]:
        """Raw firewall-zone objects (incl. each zone's network_ids membership)."""
        return self._request("GET", self._path("zones")) or []

    def list_networks(self) -> list[Network]:
        """Live L3 networks joined to their firewall zone. Read-only context for
        rule analysis; the reconciler never writes networks."""
        return build_network_map(
            self._request("GET", self._path("networks")) or [], self.raw_zones()
        )
