#!/usr/bin/env bash
# Smoke test for the openshell-gateway rock.
# Invoked by the CI build job after rockcraft-pack.
# Proves: binaries present and runnable, correct runtime-deps, no sqlite3,
# /var/run/openshell scaffold correct, non-root default user, no baked layer.
set -euo pipefail

ROCK_DIR="${ROCK_DIR:-rocks/openshell-gateway}"
IMAGE="openshell-gateway:test"

# ---------------------------------------------------------------------------
# Guard: Docker daemon must be available to the current user (no sudo).
# ---------------------------------------------------------------------------
docker info > /dev/null 2>&1 \
  || { echo "ERROR: Docker daemon is not available to the current user — smoke test requires docker (ensure the user is in the 'docker' group or Docker is rootless)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Locate packed rock and load it into the local Docker daemon.
# ---------------------------------------------------------------------------
ROCK_FILE=$(ls "${ROCK_DIR}"/*.rock 2>/dev/null | head -1)
if [[ -z "${ROCK_FILE}" ]]; then
  echo "ERROR: no .rock file found in ${ROCK_DIR}" >&2
  exit 1
fi
echo "Using rock: ${ROCK_FILE}"

SKOPEO=$(command -v skopeo 2>/dev/null || echo /snap/bin/rockcraft.skopeo)
echo "Using skopeo: ${SKOPEO}"
# --insecure-policy is required because the rockcraft.skopeo snap does not ship
# a default /etc/containers/policy.json. We are copying a locally-built OCI
# archive into the local Docker daemon, so signature policy enforcement is not
# applicable here.
"${SKOPEO}" copy --insecure-policy "oci-archive:${ROCK_FILE}" "docker-daemon:${IMAGE}"

# ---------------------------------------------------------------------------
# Helper: run a one-shot command inside the image.
# ---------------------------------------------------------------------------
run_in_rock() {
  docker run --rm --entrypoint "" "${IMAGE}" "$@"
}

# ---------------------------------------------------------------------------
# 1. Binaries are executable and respond to --help (exits 0).
# ---------------------------------------------------------------------------
echo "==> Check: openshell-gateway --help"
docker run --rm --entrypoint /usr/bin/openshell-gateway "${IMAGE}" --help

echo "==> Check: openshell-driver-lxd --help"
DRIVER_HELP=$(docker run --rm --entrypoint /usr/bin/openshell-driver-lxd "${IMAGE}" --help)

echo "==> Check: openshell-driver-lxd advertises --lxd-url"
grep -q -- '--lxd-url' <<<"${DRIVER_HELP}" \
  || { echo "ERROR: openshell-driver-lxd --help does not advertise --lxd-url; driver pin regressed to a build without the LXD client" >&2; exit 1; }

echo "==> Check: openshell-driver-lxd advertises --gateway-endpoint"
grep -q -- '--gateway-endpoint' <<<"${DRIVER_HELP}" \
  || { echo "ERROR: openshell-driver-lxd --help does not advertise --gateway-endpoint; driver build regressed" >&2; exit 1; }

echo "==> Check: openshell-driver-lxd advertises --lxd-server-fingerprint"
grep -q -- '--lxd-server-fingerprint' <<<"${DRIVER_HELP}" \
  || { echo "ERROR: openshell-driver-lxd --help does not advertise --lxd-server-fingerprint; driver build regressed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. Binaries exist at expected stable paths.
# ---------------------------------------------------------------------------
echo "==> Check: binary paths"
run_in_rock test -x /usr/bin/openshell-gateway
run_in_rock test -x /usr/bin/openshell-driver-lxd

# ---------------------------------------------------------------------------
# 3. Runtime-deps present; sqlite3 absent.
# ---------------------------------------------------------------------------
echo "==> Check: iproute2 (ip)"
run_in_rock sh -c 'ip -V'

echo "==> Check: ca-certificates bundle present"
run_in_rock test -f /etc/ssl/certs/ca-certificates.crt

echo "==> Check: sqlite3 absent"
if run_in_rock sh -c 'command -v sqlite3' 2>/dev/null; then
  echo "ERROR: sqlite3 should not be in the image" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. /var/run/openshell exists, mode 0755, owned by UID 584792.
# ---------------------------------------------------------------------------
echo "==> Check: /var/run/openshell scaffold"
STAT=$(run_in_rock stat -c "%u %g %a" /var/run/openshell)
OWNER=$(echo "${STAT}" | awk '{print $1}')
GROUP=$(echo "${STAT}" | awk '{print $2}')
MODE=$(echo "${STAT}" | awk '{print $3}')

[[ "${OWNER}" == "584792" ]] \
  || { echo "ERROR: /var/run/openshell owner is ${OWNER}, expected 584792" >&2; exit 1; }
[[ "${GROUP}" == "584792" ]] \
  || { echo "ERROR: /var/run/openshell group is ${GROUP}, expected 584792" >&2; exit 1; }
[[ "${MODE}" == "755" ]] \
  || { echo "ERROR: /var/run/openshell mode is ${MODE}, expected 755" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 5. Image runs as UID 584792 (non-root); no baked Pebble service layer.
# ---------------------------------------------------------------------------
echo "==> Check: default user is 584792"
IMAGE_USER=$(docker inspect "${IMAGE}" --format '{{.Config.User}}')
# rockcraft may set User as "584792" or "584792:584792"
[[ "${IMAGE_USER}" =~ ^584792 ]] \
  || { echo "ERROR: image User is '${IMAGE_USER}', expected 584792 (or 584792:584792)" >&2; exit 1; }

echo "==> Check: no baked Pebble service layer"
LAYER_COUNT=$(run_in_rock sh -c \
  'ls /var/lib/pebble/default/layers/ 2>/dev/null | wc -l' || echo 0)
[[ "${LAYER_COUNT}" == "0" ]] \
  || { echo "ERROR: found ${LAYER_COUNT} baked Pebble layer(s); expected none (C3)" >&2; exit 1; }

# ---------------------------------------------------------------------------
echo "All smoke checks passed."
