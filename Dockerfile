# Minimal, non-root reconciler image. Defaults to a read-only `plan`; the
# deploying chart overrides the args to run `apply` (see the example chart at
# github.com/gattjoe/pathfinder → unifi-firewall/chart).
FROM python:3.14.5-slim@sha256:af79f947dee1c929919b0488d20db7200d8737e00f68ee4abeef1fcf1fe05939 AS build
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --target /install .

FROM python:3.14.5-slim@sha256:af79f947dee1c929919b0488d20db7200d8737e00f68ee4abeef1fcf1fe05939
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/install"
COPY --from=build /install /install
# Drop to an unprivileged uid (matches chart securityContext runAsUser: 1001).
RUN useradd -u 1001 -m runner
USER 1001
ENTRYPOINT ["python", "-m", "unifi_reconciler.cli"]
CMD ["--rules", "/rules", "plan"]
