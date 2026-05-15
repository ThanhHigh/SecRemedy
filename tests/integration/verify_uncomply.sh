#!/usr/bin/env bash
# verify_uncomply.sh
# For each nginx config folder in 12_uncomply/:
#   1. Copy it into ./workspace
#   2. Build + start nginx container
#   3. Run nginx -t inside container
#   4. Record PASS/FAIL
#   5. Teardown

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="${SCRIPT_DIR}/tmp"
WORKSPACE_DIR="${SCRIPT_DIR}/workspace"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
CONTAINER_NAME="nginx_sec_remedy_test"
RESULTS_FILE="${SCRIPT_DIR}/verify_results.txt"

# ── Colors ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

# ── Pre-flight ──────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found." >&2; exit 1
fi

TARGET_PORT="${1:-}"

rm -rf "${WORKSPACE_DIR}"
rm -rf "${TMP_DIR}"
mkdir -p "${WORKSPACE_DIR}"
mkdir -p "${TMP_DIR}"

if [[ -n "${TARGET_PORT}" ]]; then
    info "Filtering for port: ${TARGET_PORT}"
    # Use find to copy specific port folder if it exists
    find "${SCRIPT_DIR}" -type d -name "nginx_raw_${TARGET_PORT}" -exec cp -r {} "${TMP_DIR}/" \;

    if [[ -z $(ls -A "${TMP_DIR}") ]]; then
        fail "No folders found matching nginx_raw_${TARGET_PORT}"
        exit 1
    fi
else
    cp -r "${SCRIPT_DIR}"/*_compliant/*/nginx_raw_* "${TMP_DIR}/"
fi

> "${RESULTS_FILE}"  # truncate results file

total=0; passed=0

# ── Build image once ────────────────────────────────────────────────────
info "Building Docker image..."
docker compose -f "${COMPOSE_FILE}" build --quiet || { echo "ERROR: Docker image build failed." >&2; exit 1; }

# ── Iterate config folders ──────────────────────────────────────────────
for config_dir in "${TMP_DIR}"/nginx_raw_*/; do
    folder_name="$(basename "${config_dir}")"
    total=$((total + 1))

    info "─── Testing: ${folder_name} ───────────────────────────────"

    # 1. Sync config into workspace (clean copy)
    rm -rf "${WORKSPACE_DIR:?}"/*
    cp -r "${config_dir}"/* "${WORKSPACE_DIR}/"

    # 2. Start container (fresh each run)
    docker compose -f "${COMPOSE_FILE}" up -d 2>/dev/null

    # 3. Wait briefly for container to be ready
    sleep 1

    # 4. Run nginx -t
    nginx_output="$(docker exec "${CONTAINER_NAME}" nginx -t 2>&1 || true)"

    # 5. Evaluate result
    if echo "${nginx_output}" | grep -q "syntax is ok"; then
        pass "${folder_name}"
        echo "PASS: ${folder_name}" >> "${RESULTS_FILE}"
        passed=$((passed + 1))
    else
        fail "${folder_name}"
        echo "FAIL: ${folder_name}" >> "${RESULTS_FILE}"

        {
            echo "--- NGINX -T OUTPUT ---"
            echo "${nginx_output}"
            echo "--- CONTAINER LOGS ---"
            docker logs "${CONTAINER_NAME}" 2>&1 || echo "Could not get logs"
            echo "-----------------------"
        } | sed 's/^/       /' >> "${RESULTS_FILE}"

        rm -rf "${TMP_DIR}"
        echo ""
        echo "════════════════════════════════════"
        echo " Results: ${passed}/${total} passed"
        echo " Full log: ${RESULTS_FILE}"
        echo "════════════════════════════════════"
        {
            echo ""
            echo "=== SUMMARY ==="
            echo "Total: ${total} | Passed: ${passed}"
        } >> "${RESULTS_FILE}"

        exit 1
    fi

    # 6. Teardown
    docker compose -f "${COMPOSE_FILE}" down --timeout 5 2>/dev/null
done

rm -rf "${WORKSPACE_DIR}"
rm -rf "${TMP_DIR}"

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo " Results: ${passed}/${total} passed"
echo " Full log: ${RESULTS_FILE}"
echo "════════════════════════════════════"

{
    echo ""
    echo "=== SUMMARY ==="
    echo "Total: ${total} | Passed: ${passed}"
} >> "${RESULTS_FILE}"
