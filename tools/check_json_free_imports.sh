#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${CONDA_PREFIX:-}" ]]; then
    echo "CONDA_PREFIX is not set; run this check through Pixi" >&2
    exit 1
fi

shopt -s nullglob
rejected_packages=(
    "$CONDA_PREFIX"/conda-meta/json-*.json
    "$CONDA_PREFIX"/conda-meta/max-*.json
    "$CONDA_PREFIX"/conda-meta/simdjson-*.json
)

if (( ${#rejected_packages[@]} > 0 )); then
    echo "default environment contains rejected JSON dependencies:" >&2
    printf '  %s\n' "${rejected_packages[@]}" >&2
    exit 1
fi

mojo -I . tests/http/test_json_free_imports.mojo
