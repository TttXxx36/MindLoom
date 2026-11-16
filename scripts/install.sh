#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MEM_CLI="${REPO_ROOT}/cli/mem.mjs"

AUTHORIZE=0
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--authorize-autosync" ]]; then
    AUTHORIZE=1
  fi
  ARGS+=("$arg")
done

if [[ "$AUTHORIZE" -eq 1 ]]; then
  if [[ ! -t 0 ]] || \
     [[ -n "${ANTIGRAVITY_AGENT:-}" ]] || \
     [[ -n "${CODEX_SANDBOX:-}" ]] || \
     [[ -n "${CODEX_CI:-}" ]] || \
     [[ -n "${CODEX_THREAD_ID:-}" ]] || \
     [[ -n "${CLAUDECODE:-}" ]] || \
     [[ -n "${GEMINI_CLI:-}" ]] || \
     [[ -n "${CURSOR_AGENT:-}" ]] || \
     [[ -n "${CI:-}" ]]; then
    echo "ACCESS_DENIED (EXIT 43): install.sh --authorize-autosync is restricted to interactive human terminals only." >&2
    exit 43
  fi
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js >= 22.15.0 is required." >&2
  exit 1
fi

NODE_VER="$(node -p "process.versions.node")"
NODE_MAJOR="${NODE_VER%%.*}"
NODE_REST="${NODE_VER#*.}"
NODE_MINOR="${NODE_REST%%.*}"
if [[ "$NODE_MAJOR" -lt 22 ]] || \
   { [[ "$NODE_MAJOR" -eq 22 ]] && [[ "$NODE_MINOR" -lt 15 ]]; } || \
   { [[ "$NODE_MAJOR" -eq 23 ]] && [[ "$NODE_MINOR" -lt 8 ]]; }; then
  echo "Error: Node.js 22 LTS (>= 22.15.0) or Node.js 24+ (or >= 23.8.0) is required (found v${NODE_VER})." >&2
  exit 1
fi

if ! node -e "const z = require('node:zlib'); const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(':memory:'); db.close(); if (typeof z.zstdCompressSync !== 'function' || typeof z.zstdDecompressSync !== 'function') process.exit(2);"; then
  echo "Error: Node.js runtime lacks built-in node:sqlite or node:zlib Zstd support (v${NODE_VER})." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required on PATH." >&2
  exit 1
fi

exec node "$MEM_CLI" setup "${ARGS[@]}"
