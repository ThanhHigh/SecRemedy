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
UNCOMPLY_DIR="${SCRIPT_DIR}/12_uncomply"
WORKSPACE_DIR="${SCRIPT_DIR}/workspace"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
CONTAINER_NAME="nginx_sec_remedy_test"
RESULTS_FILE="${SCRIPT_DIR}/verify_results.txt"

# ── Colors ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

# ── Pre-flight ──────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found." >&2; exit 1
fi

mkdir -p "${WORKSPACE_DIR}"
> "${RESULTS_FILE}"  # truncate results file

total=0; passed=0; failed=0

# ── Build image once ────────────────────────────────────────────────────
info "Building Docker image..."
docker compose -f "${COMPOSE_FILE}" build --quiet

# ── Iterate config folders ──────────────────────────────────────────────
for config_dir in "${UNCOMPLY_DIR}"/nginx_raw_*/; do
    folder_name="$(basename "${config_dir}")"
    total=$((total + 1))

    info "─── Testing: ${folder_name} ───────────────────────────────"

    # 1. Sync config into workspace (clean copy)
    # rm -rf "${WORKSPACE_DIR:?}"/*
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

        failed=$((failed + 1))
    fi

    # Print nginx -t output for visibility
    echo "${nginx_output}" | sed 's/^/  > /'

    # 6. Teardown
    rm -rf "${WORKSPACE_DIR:?}"/*
    docker compose -f "${COMPOSE_FILE}" down --timeout 5 2>/dev/null
done

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo " Results: ${passed}/${total} passed, ${failed} failed"
echo " Full log: ${RESULTS_FILE}"
echo "════════════════════════════════════"

{
    echo ""
    echo "=== SUMMARY ==="
    echo "Total: ${total} | Passed: ${passed} | Failed: ${failed}"
} >> "${RESULTS_FILE}"

# Exit non-zero if any failed
[ "${failed}" -eq 0 ]
