# unifi-reconciler reconciler — build/test/run targets.
# docker target builds linux/amd64 and pushes to GHCR (CI does this on tags too);
# macos builds an arm64 image for local use.

REGISTRY ?= ghcr.io/gattjoe
IMAGE    ?= $(REGISTRY)/unifi-reconciler
TAG      ?= latest
RULES    ?= ./examples/rules

# Prefer the project venv if it exists, so `make plan/apply/export` work without
# manually activating it. Override with `make PY=… <target>` if needed.
PY  ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
# The package is src-layout and not installed; put src on the path so `-m` works
# whether or not it was editable-installed.
CLI := PYTHONPATH=src $(PY) -m unifi_reconciler.cli --rules $(RULES)

.PHONY: venv test plan apply export introspect networks docker macos clean

venv:
	$(PY) -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'

test:
	PYTHONPATH=src $(PY) -m pytest -q

# Local read-only plan against the live UDM. Needs UDM_HOST, UNIFI_USERNAME,
# UNIFI_PASSWORD, UDM_CA_FINGERPRINT in the environment (or a .env you source).
plan:
	$(CLI) plan

apply:
	$(CLI) apply --confirm --backup-file backup.json

# Read-only import of all live policies into RULES (writes YAML + managed-state.json
# + an uncommitted export-raw.json sidecar). Same env as `make plan`.
export:
	$(CLI) export

introspect:
	$(CLI) introspect

# Read-only: list live L3 networks + their firewall zones. Same env as `make plan`.
# `make networks WRITE=--write` scaffolds networks.yaml in RULES from the map.
networks:
	$(CLI) networks $(WRITE)

docker:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) --push .
	docker inspect --format='{{index .RepoDigests 0}}' $(IMAGE):$(TAG)
macos:
	docker buildx build --platform linux/arm64 -t $(IMAGE):$(TAG)-arm64 --load .

clean:
	rm -rf .venv .pytest_cache backup.json src/*.egg-info
