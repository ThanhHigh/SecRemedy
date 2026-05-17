#!/usr/bin/env bash
# run_remedy_all.sh
# Dry-run (or execute) remedy_engine on every port in before_remediation.json.
#
# Usage:
#   ./scripts/run_remedy_all.sh                  # dry-run all ports
#   ./scripts/run_remedy_all.sh --execute        # execute all ports (SSH push)
#   ./scripts/run_remedy_all.sh --execute --host 127.0.0.1 --ssh-port 22 \
#       --user root --pass secret                # execute with custom creds
#
# Output:
#   Logs per-port to logs/remedy_<port>.log
#   Summary printed at end: OK / FAILED / NO_CHANGES counts

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/tests/configs/before_remediation.json"
LOG_DIR="$PROJECT_ROOT/logs/remedy_runs"
PYTHON="${PYTHON:-python}"

# ---------------------------------------------------------------------------
# Parse flags (pass-through extra args to remedy_engine)
# ---------------------------------------------------------------------------
MODE="--dry-run"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute)
            MODE="--execute"
            shift
            ;;
        --host|--ssh-port|--user|--pass|--key)
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        *)
            echo "[!] Unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate deps
# ---------------------------------------------------------------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Config not found: $CONFIG_FILE" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "[ERROR] jq required. Install: sudo apt install jq" >&2
    exit 1
fi

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Collect ports
# ---------------------------------------------------------------------------
mapfile -t PORTS < <(jq -r '.servers[].port' "$CONFIG_FILE")
TOTAL=${#PORTS[@]}

echo "========================================"
echo " SecRemedy Batch Remedy Engine"
echo " Mode    : $MODE"
echo " Servers : $TOTAL"
echo " Config  : $CONFIG_FILE"
echo " Logs    : $LOG_DIR"
echo "========================================"
echo ""

# ---------------------------------------------------------------------------
# Run per port
# ---------------------------------------------------------------------------
OK=0; FAILED=0; NO_CHANGES=0

for PORT in "${PORTS[@]}"; do
    LOG_FILE="$LOG_DIR/remedy_${PORT}.log"
    printf "[*] Port %-6s → " "$PORT"

    CMD=("$PYTHON" -m core.remedyEng.remedy_engine "$MODE" --port "$PORT")
    [[ ${#EXTRA_ARGS[@]} -gt 0 ]] && CMD+=("${EXTRA_ARGS[@]}")

    # Run from project root so relative paths resolve correctly
    set +e
    (cd "$PROJECT_ROOT" && "${CMD[@]}") > "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    set -e

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo "FAILED  (exit $EXIT_CODE) — see $LOG_FILE"
        ((FAILED++))
    else
        # Detect no_changes vs pending from log output
        if grep -q "no_changes\|No changes needed" "$LOG_FILE" 2>/dev/null; then
            echo "NO_CHANGES"
            ((NO_CHANGES++))
        else
            STATUS=$(grep -oP "Status\s*:\s*\K\S+" "$LOG_FILE" 2>/dev/null | head -1 || echo "ok")
            echo "OK  [$STATUS]"
            ((OK++))
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo " Summary"
echo "   Total     : $TOTAL"
echo "   OK        : $OK"
echo "   No changes: $NO_CHANGES"
echo "   Failed    : $FAILED"
echo "========================================"

[[ $FAILED -gt 0 ]] && exit 1 || exit 0
