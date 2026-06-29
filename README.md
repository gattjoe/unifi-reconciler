# unifi-reconciler

Declarative, GitOps-style management of the **UniFi UDM SE** zone-based
firewall. Author firewall policies as YAML, review the diff, and apply it to the
gateway — no more click-ops in the UniFi UI.

`unifi-reconciler` is a small, dependency-light Python CLI. Run it directly on your Mac
(python mode), in CI, or as a container in Kubernetes.

## How it works

```
  author YAML  ──►  unifi-reconciler plan  ──►  review diff  ──►  unifi-reconciler apply
  (desired state)   (read live,         (PR / eyeball)    (cookie+CSRF,
                     dry-run diff)                          TLS-pinned → UDM v2 API)
```

- **Engine**: the internal UniFi **v2** API (`/proxy/network/v2/api`, cookie+CSRF
  login). It is the only surface that exposes firewall policies with a stable
  per-rule `_id` on current controllers — the official Integration API
  (`/proxy/network/integration/v1`, `X-API-KEY`) returns `401` for firewall policies.
- **Auth**: logs in with a local-admin **username/password** (`UNIFI_USERNAME`
  / `UNIFI_PASSWORD`), captures the `TOKEN` cookie + CSRF token, and carries the
  rotating CSRF token across requests. TLS is **pinned** to the UDM's self-signed
  leaf cert (`UDM_CA_FINGERPRINT`).
- **Writes**: **update** and **delete** are live. Updates are **read-modify-write**
  — the reconciler fetches the live raw policy, overlays only the fields the model
  owns (enabled, action, index, logging, zones, and `ips` on IP-target rules), and
  PUTs it back, so the v2 `matching_target` union (CLIENT/WEB/NETWORK/APP/…) and all
  v2-only fields (schedule, connection states, ip-version) are preserved untouched.
  **Create** is intentionally not supported — author new rules in the UI and adopt
  them with `unifi-reconciler export` (the union can't be expressed in the declarative model).
- **Authority — explicit ledger**: the tool owns exactly the policies listed in
  `managed-state.json` (keyed by policy name). Only ledger rules are ever updated
  or deleted. Rules you make by hand in the UI (and built-in/predefined rules) are
  invisible until you adopt them with `export`. No name prefix — names mirror the
  real UniFi names.

## Install / run (python mode)

The package is a standard src-layout console script — no Docker required.

```bash
# zero-install, from a checkout
uvx --from . unifi-reconciler --rules ./examples/rules plan

# or editable install into a venv
make venv          # python -m venv .venv && pip install -e '.[dev]'
unifi-reconciler --rules ./rules plan
```

Set the v2 environment (copy `.env.example` to `.env` and source it):

```
UDM_HOST=192.168.1.1
UNIFI_USERNAME=local-admin
UNIFI_PASSWORD=…
UDM_CA_FINGERPRINT=…        # see "capture the fingerprint" below
```

### Capture the TLS fingerprint (one-time)

The UDM serves a self-signed cert; we pin it rather than disabling verification:

```bash
UDM_HOST=192.168.1.1 UNIFI_USERNAME=… UNIFI_PASSWORD=… UNIFI_INSECURE_TLS=1 \
  unifi-reconciler introspect 2>&1 | grep fingerprint
```

Copy the printed SHA-256 into your env (`UDM_CA_FINGERPRINT`). Re-capture if the
UDM cert is regenerated.

## CLI

```
unifi-reconciler --rules <dir> <command>

  plan        read-only diff of desired (YAML) vs. live firewall policies
  apply       apply the diff   (dry-run unless --confirm or APPLY=1; --backup-file FILE)
  export      import every live policy into <dir> (YAML + managed-state.json ledger)
  introspect  dump one raw live policy set (schema/fingerprint discovery)
  networks    list live L3 networks + their zones (--write scaffolds networks.yaml)
```

The `Makefile` wraps these: `make plan`, `make apply`, `make export`,
`make introspect`, `make networks` (all read the same env).

## The rule schema

```yaml
apiVersion: firewall.echobase.network/v1
kind: FirewallPolicy
metadata:
  name: Block IoT to Internal        # the real UniFi name; ownership is the ledger
  id: 64f…a1                          # the live policy's _id; set by `export`
spec:
  enabled: true
  action: BLOCK                      # ALLOW | BLOCK | REJECT
  index: 2000                        # ordering within the zone pair
  source:      { zone: External }    # zone by name; optional ips:/ports: refinements
  destination: { zone: Internal }
  protocol: all                      # all | tcp | udp | icmp
  logging: true
  description: "..."
```

A policy is managed iff its `name` appears in the ledger:

```json
// managed-state.json
{
  "apiVersion": "firewall.echobase.network/v1",
  "kind": "ManagedState",
  "managed": [ { "name": "Block IoT to Internal", "id": "64f…a1" } ]
}
```

Zones are referenced by name and resolved to ids at apply time. Zones themselves
stay managed in the UI; `zones.yaml` documents them and is validated against the
live controller. See `examples/rules/` for a minimal working tree.

## Importing existing rules (one-time adoption)

Already have a pile of UI-made rules? Bring them under code management in one pass:

```bash
make export   # read-only: GETs every live policy, writes YAML + the ledger locally
```

`export` writes, under `<rules>/`: `policies/<slug>.yaml` (one doc per live rule,
real name preserved), `managed-state.json` (the ownership ledger), and
`export-raw.json` (full raw wire objects, gitignored — your fidelity-review
artifact). Built-in/**predefined** rules are skipped, so you can't accidentally
delete a system rule. Then `make plan` should report no changes.

> ### ⚠️ Fidelity caveat — read before you `apply`
> The declarative model captures a *subset* of a policy. A zone-based rule can
> carry fields the model does **not** represent (connection states, ip-version,
> match-opposite, schedules, port/IP groups, ICMP types). **`apply` sends only
> modeled fields**, so adopting a rule that uses an unmodeled field and then
> applying it would *strip* it — and `plan` won't warn you. `export` is the only
> place this is visible: it prints `[LOSSY: …]` per rule. For any `[LOSSY]` rule,
> extend the model (`model.py` + the mapping in `client.py`) before adopting it,
> or leave it out of the ledger and keep managing it in the UI.

## Safety guardrails (`src/unifi_reconciler/safety.py`)

- **Delete/update protection** — only ledger policies are ever mutated; touching
  anything else aborts the whole run.
- **Conflict protection** — a desired rule whose name matches a live rule *not* in
  the ledger is refused (would create a duplicate); adopt it via `export` first.
- **Predefined protection** — built-in/system rules are never adopted or deleted.
- **Lockout protection** — a broad `BLOCK`/`REJECT` sourced from an admin zone
  (`UNIFI_ADMIN_ZONES`, default `Internal`) with no ip/port scoping is refused, so
  you can't fence yourself out of the gateway. Best-effort: it won't catch a block
  that targets the gateway via `destination.ips`, or sources from a differently
  named admin zone.
- **Backup before apply** — the pre-change owned policy set is dumped (stdout +
  optional `--backup-file`); revert = re-apply the backup.
- **Dry-run default** — `apply` requires `--confirm` (or `APPLY=1`).

## Deploying in Kubernetes

The image runs the CLI as its entrypoint (`python -m unifi_reconciler.cli`, defaulting to
a read-only `plan`). A deploying chart mounts the rules as a ConfigMap at `/rules`
and overrides the args to `apply --confirm`. 

## Build & release

```bash
make docker     # build linux/amd64 and push to $(IMAGE) (default ghcr.io/gattjoe/unifi-reconciler)
make macos      # build a local arm64 image
```

Pushing a `v*` git tag triggers `.github/workflows/release.yml`, which builds and
publishes `ghcr.io/gattjoe/unifi-reconciler:<tag>` + `:latest` to the GitHub Container
Registry and prints the image digest in the job summary (pin that digest in your
deployment).

## Tests

```bash
make test       # offline pytest suite, no UDM needed
```

> **API-schema caveat:** the UniFi firewall schema keeps expanding release to
> release. All endpoint paths and JSON field mappings live in one file —
> `src/unifi_reconciler/client.py`. If a field name is off on your controller,
> `unifi-reconciler introspect` shows the real shape and the fix is usually a one-line
> edit there; the rest of the package is wire-neutral and unit-tested.

## License

Apache 2.0 — see `LICENSE`.
