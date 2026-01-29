#!/usr/bin/env bash
#
# Wrapper for running this fork as a locally-built "binary".
# - Optionally syncs from an upstream git remote (default: `upstream`, fallback: `origin`)
# - Rebuilds codex-rs/cli
# - Executes the built `codex` binary, forwarding all remaining args
#
# Typical setup:
#   chmod +x /path/to/repo/scripts/codex-fork.sh
#   ln -sf /path/to/repo/scripts/codex-fork.sh ~/bin/codex
#
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  codex-fork.sh [options] [--] [codex args...]

Options:
  --no-sync            Skip git fetch/rebase step
  --sync-only          Only sync (do not build/run)
  --rebuild-only       Only build (do not sync/run)
  --release            Build/run release binary
  --debug              Build/run debug binary (default)
  --remote <name>      Git remote to sync from (default: upstream, fallback: origin)
  --branch <name>      Remote branch to rebase onto (default: remote HEAD, fallback: main)
  --merge              Use merge (ff-only) instead of rebase
  --rebase             Use rebase (default)
  --allow-dirty        Allow sync/build with a dirty working tree (not recommended)
  -h, --help           Show this help

Examples:
  codex-fork.sh -- --help
  codex-fork.sh --release -- --version
  codex-fork.sh --remote upstream --branch main
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
codex_rs_dir="${repo_root}/codex-rs"

sync=1
sync_only=0
build_only=0
profile="debug"
strategy="rebase"
allow_dirty=0
remote="${CODEX_FORK_UPSTREAM_REMOTE:-upstream}"
branch=""

while [[ $# -gt 0 ]]; do
  case "${1}" in
    --no-sync) sync=0 ;;
    --sync-only) sync_only=1 ;;
    --rebuild-only) build_only=1 ;;
    --release) profile="release" ;;
    --debug) profile="debug" ;;
    --remote)
      remote="${2:-}"
      shift
      ;;
    --branch)
      branch="${2:-}"
      shift
      ;;
    --merge) strategy="merge" ;;
    --rebase) strategy="rebase" ;;
    --allow-dirty) allow_dirty=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: ${1}" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
  shift
done

if [[ ! -d "${codex_rs_dir}" ]]; then
  echo "Failed to locate codex-rs at ${codex_rs_dir}" >&2
  exit 2
fi

if ! git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Not a git repository: ${repo_root}" >&2
  exit 2
fi

if ! git -C "${repo_root}" remote get-url "${remote}" >/dev/null 2>&1; then
  remote="origin"
fi

if [[ -z "${branch}" ]]; then
  remote_head_ref="$(git -C "${repo_root}" symbolic-ref -q --short "refs/remotes/${remote}/HEAD" 2>/dev/null || true)"
  if [[ -n "${remote_head_ref}" ]]; then
    branch="${remote_head_ref#*/}"
  else
    branch="main"
  fi
fi

if [[ "${allow_dirty}" -eq 0 ]]; then
  if [[ -n "$(git -C "${repo_root}" status --porcelain)" ]]; then
    echo "Working tree is dirty. Commit/stash your changes first, or pass --allow-dirty." >&2
    exit 2
  fi
fi

if [[ "${sync}" -eq 1 ]]; then
  echo "[codex-fork] Fetching ${remote}..." >&2
  git -C "${repo_root}" fetch "${remote}" --prune

  upstream_ref="${remote}/${branch}"
  if ! git -C "${repo_root}" rev-parse -q --verify "${upstream_ref}" >/dev/null 2>&1; then
    echo "Upstream ref not found: ${upstream_ref}" >&2
    exit 2
  fi

  if [[ "${strategy}" == "merge" ]]; then
    echo "[codex-fork] Merging (ff-only) ${upstream_ref}..." >&2
    git -C "${repo_root}" merge --ff-only "${upstream_ref}"
  else
    echo "[codex-fork] Rebasing onto ${upstream_ref}..." >&2
    git -C "${repo_root}" rebase "${upstream_ref}"
  fi
fi

if [[ "${sync_only}" -eq 1 ]]; then
  exit 0
fi

echo "[codex-fork] Building codex (${profile})..." >&2
if [[ "${profile}" == "release" ]]; then
  (cd "${codex_rs_dir}" && cargo build -p codex-cli --release)
  bin="${codex_rs_dir}/target/release/codex"
else
  (cd "${codex_rs_dir}" && cargo build -p codex-cli)
  bin="${codex_rs_dir}/target/debug/codex"
fi

if [[ "${build_only}" -eq 1 ]]; then
  echo "${bin}"
  exit 0
fi

if [[ ! -x "${bin}" ]]; then
  echo "Built binary not found/executable: ${bin}" >&2
  exit 2
fi

exec "${bin}" "$@"

