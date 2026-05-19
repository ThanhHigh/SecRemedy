#!/usr/bin/env bash
# docker_server.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
WORKSPACE_DIR="${SCRIPT_DIR}/workspace"
RAW_CONFIGS_DIR="${PROJECT_ROOT}/tmp/raw_configs"

usage() {
	echo "Usage: $(basename "$0") <port>" >&2
}

cleanup() {
	local exit_code=$?

	trap - EXIT INT TERM

	if [[ -n "${NGINX_PORT:-}" ]]; then
		NGINX_PORT="${NGINX_PORT}" docker compose -f "${COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true
	fi

	rm -rf "${WORKSPACE_DIR}"

	exit "${exit_code}"
}

trap cleanup EXIT INT TERM

if [[ $# -ne 1 ]]; then
	usage
	exit 1
fi

NGINX_PORT="$1"

if [[ ! "${NGINX_PORT}" =~ ^[0-9]+$ ]]; then
	echo "ERROR: port must be numeric." >&2
	usage
	exit 1
fi

if (( NGINX_PORT < 1 || NGINX_PORT > 65535 )); then
	echo "ERROR: port must be between 1 and 65535." >&2
	exit 1
fi

SOURCE_DIR="${RAW_CONFIGS_DIR}/${NGINX_PORT}"

if [[ ! -d "${SOURCE_DIR}" ]]; then
	echo "ERROR: missing config folder: ${SOURCE_DIR}" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker not found." >&2
	exit 1
fi

rm -rf "${WORKSPACE_DIR}"
mkdir -p "${WORKSPACE_DIR}"
cp -R "${SOURCE_DIR}"/. "${WORKSPACE_DIR}/"

echo "Starting nginx container for port ${NGINX_PORT}..."
echo "Source config: ${SOURCE_DIR}"
echo "Workspace: ${WORKSPACE_DIR}"

NGINX_PORT="${NGINX_PORT}" docker compose -f "${COMPOSE_FILE}" up --build
