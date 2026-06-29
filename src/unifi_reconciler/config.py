"""Runtime configuration, sourced from environment variables.

Nothing secret is hard-coded. The v2 API logs in with a local-admin
``UNIFI_USERNAME`` / ``UNIFI_PASSWORD`` (a K8s Secret in-cluster, or a local env
var / .env when running ``make plan`` from the Mac). TLS is pinned to the UDM's
self-signed leaf certificate via a SHA-256 fingerprint — we never disable
verification.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Network site ids are opaque alphanumeric tokens; reject anything that could
# alter a URL path when interpolated.
_SITE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


@dataclass(frozen=True)
class Config:
    host: str
    """UDM management host/IP, no scheme (e.g. ``192.168.1.1``)."""

    site: str
    """Internal site shortname for the v2 API (usually ``'default'``)."""

    username: str | None
    """Local admin username for the v2 cookie+CSRF login. Required."""

    password: str | None
    """Local admin password for the v2 cookie+CSRF login. Required."""

    ca_fingerprint: str | None
    """Expected SHA-256 fingerprint of the UDM leaf cert, lowercase hex, colons optional.

    When set, the HTTPS connection is verified against this pin. When unset, the
    client refuses to run unless ``insecure_tls`` is explicitly enabled — there is
    no silent ``verify=False`` path.
    """

    insecure_tls: bool
    """Escape hatch for first-run fingerprint capture only. Never set in-cluster."""

    timeout: float
    """Per-request timeout in seconds."""

    admin_zones: tuple[str, ...]
    """Zones the operator administers the UDM from; a broad BLOCK/REJECT out of one
    is refused as a lockout risk. From ``UNIFI_ADMIN_ZONES`` (comma-separated)."""

    admin_networks: tuple[str, ...]
    """Networks within admin zones that represent the management plane; a managed
    BLOCK/REJECT scoped to one of these is also refused as a lockout risk.
    From ``UNIFI_ADMIN_NETWORKS`` (comma-separated). Default: ``Default``.

    .. note:: The default name ``Default`` matches the admin LAN on this specific
       controller. On a different deployment the primary LAN may be named differently
       (``LAN``, ``Trusted``, etc.) — set ``UNIFI_ADMIN_NETWORKS`` explicitly to match
       your actual admin network name, or clear it to rely on zone-level protection only.
    """

    admin_dst_zones: tuple[str, ...]
    """Destination zones that constitute the management plane. The broad-block lockout
    check only fires when *both* the source is an admin zone AND the destination is
    one of these zones. Blocking Internal→External is safe; blocking Internal→Gateway
    is what would cut off UDM access. From ``UNIFI_ADMIN_DST_ZONES`` (comma-separated).
    Default: ``Gateway``. Empty string disables the destination filter (old behavior:
    any broad BLOCK from an admin zone is refused regardless of destination)."""

    github_token: str
    """GitHub personal access token with repo write permission. Used to open a
    write-back PR after v2 creates assign real IDs. Empty = write back locally."""

    github_repo: str
    """GitHub repository in ``owner/name`` form (e.g. ``owner/repo``).
    Required when ``github_token`` is set. From ``GITHUB_REPO``."""

    github_rules_path: str
    """Repo-relative path to the rules directory (e.g. ``rules``). Used to
    construct file paths in the PR. From ``GITHUB_RULES_PATH``."""

    github_base_branch: str
    """Base branch for write-back PRs. Default: ``main``. From ``GITHUB_BASE_BRANCH``."""

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"

    @staticmethod
    def normalize_fingerprint(raw: str | None) -> str | None:
        if not raw:
            return None
        return raw.replace(":", "").replace(" ", "").strip().lower()


def load(env: dict[str, str] | None = None) -> Config:
    """Build a :class:`Config` from the process environment (or ``env`` for tests)."""
    src = os.environ if env is None else env

    host = src.get("UDM_HOST", "").strip()
    site = src.get("UNIFI_SITE", "default").strip()
    username = src.get("UNIFI_USERNAME", "").strip() or None
    password = src.get("UNIFI_PASSWORD", "") or None
    fingerprint = Config.normalize_fingerprint(src.get("UDM_CA_FINGERPRINT"))
    insecure = src.get("UNIFI_INSECURE_TLS", "").lower() in ("1", "true", "yes")
    timeout = float(src.get("UNIFI_TIMEOUT", "30"))
    admin_zones = tuple(
        z.strip() for z in src.get("UNIFI_ADMIN_ZONES", "Internal").split(",") if z.strip()
    ) or ("Internal",)
    admin_networks = tuple(
        n.strip() for n in src.get("UNIFI_ADMIN_NETWORKS", "Default").split(",") if n.strip()
    ) or ("Default",)
    admin_dst_zones = tuple(
        z.strip() for z in src.get("UNIFI_ADMIN_DST_ZONES", "Gateway").split(",") if z.strip()
    )
    github_token = src.get("GITHUB_TOKEN", "").strip()
    github_repo = src.get("GITHUB_REPO", "").strip()
    github_rules_path = src.get("GITHUB_RULES_PATH", "rules").strip()
    github_base_branch = src.get("GITHUB_BASE_BRANCH", "main").strip()

    # UDM_HOST is always required. Credentials (username/password) are validated
    # at the client boundary, so they are not mandatory here.
    if not host:
        raise ConfigError("missing required environment: UDM_HOST")

    if not fingerprint and not insecure:
        raise ConfigError(
            "UDM_CA_FINGERPRINT is required for TLS pinning. To capture it on first "
            "run, set UNIFI_INSECURE_TLS=1 once and read the printed fingerprint, "
            "then pin it. Never run insecure in-cluster."
        )

    if not _SITE_ID_RE.match(site):
        raise ConfigError(
            f"UNIFI_SITE {site!r} is invalid; expected an opaque id matching "
            f"{_SITE_ID_RE.pattern} (it is interpolated into request URLs)."
        )

    return Config(
        host=host,
        site=site,
        username=username,
        password=password,
        ca_fingerprint=fingerprint,
        insecure_tls=insecure,
        timeout=timeout,
        admin_zones=admin_zones,
        admin_networks=admin_networks,
        admin_dst_zones=admin_dst_zones,
        github_token=github_token,
        github_repo=github_repo,
        github_rules_path=github_rules_path,
        github_base_branch=github_base_branch,
    )
