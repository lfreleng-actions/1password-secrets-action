#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
#
# update-1password-cli-versions.sh
#
# Fetch 1Password CLI release artifacts, compute SHA256 checksums for each platform
# (binary inside the official .zip), and generate or update the YAML database:
#   1password-cli-versions.yaml
#
# Features:
# - Compute per-platform SHA256 for one or more versions
# - Print a ready-to-paste YAML snippet OR update the repository YAML in place
# - Optionally commit the change and open a PR (requires git and gh)
#
# Requirements:
# - curl
# - unzip
# - sha256sum (Linux) or shasum (macOS)
# - git (optional, for --commit)
# - gh  (optional, for --open-pr)
#
# Usage examples:
#   # Print YAML block for a specific version (no file changes)
#   scripts/update-1password-cli-versions.sh -v 2.31.1
#
#   # Update the repo YAML file in-place (create if missing), committing the change
#   scripts/update-1password-cli-versions.sh -v 2.31.1 --update-file --commit
#
#   # Fetch latest version automatically, update file, create a branch and open a PR
#   scripts/update-1password-cli-versions.sh --latest --update-file --branch "chore/op-cli-2.31.1" --commit --open-pr
#
set -Eeuo pipefail

# Globals / Defaults
BASE_URL="https://cache.agilebits.com/dist/1P/op2"
REPO_YAML_DEFAULT="1password-cli-versions.yaml"
SCHEMA_VERSION="1"

# CLI flags (defaults)
VERSIONS=()
LATEST=false
YAML_PATH="${REPO_YAML_DEFAULT}"
DO_UPDATE_FILE=false
DO_COMMIT=false
DO_OPEN_PR=false
BRANCH_NAME=""
QUIET=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -v, --version <X.Y.Z>     Add this version (repeatable). Example: -v 2.31.1
      --latest              Resolve latest release version automatically
  -f, --file <path>         YAML file path to update (default: ${REPO_YAML_DEFAULT})
      --update-file         Update the YAML file in-place (otherwise print snippet)
      --commit              Commit changes to git (implies --update-file)
      --branch <name>       Create/switch to a git branch before committing
      --open-pr             Open a GitHub PR using gh (implies --commit)
  -q, --quiet               Reduce script output (errors still printed)
  -h, --help                Show this help

Notes:
- Without --update-file, computed YAML for selected versions is printed to stdout.
- With --update-file, the script will create the YAML if missing or merge/replace version blocks if present.
- With --commit, the script will 'git add' and 'git commit' the YAML changes. Use --branch to isolate changes.
- With --open-pr, the script will attempt to create a PR using the GitHub CLI (gh).

EOF
}

log() {
  if [ "${QUIET}" = "false" ]; then
    echo "[$(basename "$0")] $*"
  fi
}

err() {
  echo "[$(basename "$0")] ERROR: $*" >&2
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command not found: $1"
    exit 1
  fi
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    err "No SHA256 tool found (sha256sum or shasum)"
    exit 1
  fi
}

# Resolve latest version from official updates endpoint.
# Endpoint returns JSON-like text; we grep the first X.Y.Z occurrence.
resolve_latest_version() {
  local url="https://app-updates.agilebits.com/check/1/0/CLI2/en/2.0.0/N"
  require_cmd curl
  local latest
  latest="$(curl -fsSL "${url}" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  if [ -z "${latest}" ]; then
    err "Failed to resolve latest version from ${url}"
    exit 1
  fi
  echo "${latest}"
}

# Download the official ZIP for a given platform and version.
download_zip() {
  local ver="$1" os="$2" arch="$3" dest="$4"
  local vtag="v${ver}"
  local url="${BASE_URL}/pkg/${vtag}/op_${os}_${arch}_${vtag}.zip"
  require_cmd curl
  log "Downloading: ${url}"
  curl -fsSL "${url}" -o "${dest}"
}

# Extract binary from ZIP to a target path.
# The ZIP contains either 'op' or 'op.exe' at top-level.
extract_binary_from_zip() {
  local zip_file="$1" out_bin="$2" expected_bin_name="$3"
  require_cmd unzip

  # Use unzip -Z1 to list files; then extract only the expected binary name.
  if unzip -Z1 "${zip_file}" | grep -qx "${expected_bin_name}"; then
    unzip -p "${zip_file}" "${expected_bin_name}" > "${out_bin}"
    chmod +x "${out_bin}" || true
  else
    err "Binary '${expected_bin_name}' not found in archive: ${zip_file}"
    return 1
  fi
}

# Compute checksums for all supported platforms for a version.
# Outputs lines: "<platform_key> <sha256>"
compute_platform_shas() {
  local ver="$1"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  # Platform matrix
  # format: key|os|arch|bin
  local matrix=(
    "linux_amd64|linux|amd64|op"
    "linux_arm64|linux|arm64|op"
    "darwin_amd64|darwin|amd64|op"
    "darwin_arm64|darwin|arm64|op"
    "windows_amd64|windows|amd64|op.exe"
  )

  for entry in "${matrix[@]}"; do
    IFS='|' read -r key os arch bin <<< "${entry}"

    local zip_path="${tmpdir}/op_${os}_${arch}_v${ver}.zip"
    local bin_path="${tmpdir}/${bin}"

    # Attempt to download
    if ! download_zip "${ver}" "${os}" "${arch}" "${zip_path}"; then
      err "Skipping ${key} (download failed for version ${ver})"
      continue
    fi

    # Extract binary and compute sha
    if ! extract_binary_from_zip "${zip_path}" "${bin_path}" "${bin}"; then
      err "Skipping ${key} (extract failed)"
      continue
    fi

    local sha
    sha="$(sha256_file "${bin_path}")"
    echo "${key} ${sha}"
  done

  rm -rf "${tmpdir}"
  trap - EXIT
}

# Generate a YAML block for a single version using provided checksums (stdin lines: "<platform> <sha>")
generate_yaml_block() {
  local ver="$1"
  declare -A kv=()
  while read -r line; do
    [ -z "${line}" ] && continue
    local key sha
    key="$(echo "${line}" | awk '{print $1}')"
    sha="$(echo "${line}" | awk '{print $2}')"
    kv["${key}"]="${sha}"
  done

  echo "  \"${ver}\":"
  for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64; do
    if [ -n "${kv[$platform]+x}" ]; then
      echo "    ${platform}: \"${kv[$platform]}\""
    fi
  done
}

# Replace (or append) version blocks in the YAML file.
# Assumptions about YAML layout:
# - Top-level keys include: schema_version, generated_at, versions
# - The 'versions:' mapping is at top-level and continues to EOF.
# - Each version block starts with two spaces then quoted semver (e.g., '  "2.31.1":')
update_yaml_file() {
  local yaml_file="$1"
  shift
  local versions_to_replace=("$@")

  # Create the file if it doesn't exist
  if [ ! -f "${yaml_file}" ]; then
    log "Creating ${yaml_file}"
    {
      echo "schema_version: ${SCHEMA_VERSION}"
      echo "generated_at: \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\""
      echo "versions:"
    } > "${yaml_file}"
  fi

  # Backup original
  local backup
  backup="${yaml_file}.bak.$(date -u +%s)"
  cp -f "${yaml_file}" "${backup}"

  # Update generated_at
  if grep -q '^generated_at:' "${yaml_file}"; then
    # Replace existing generated_at
    sed -i.bak -E "s|^generated_at:.*$|generated_at: \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"|" "${yaml_file}"
    rm -f "${yaml_file}.bak"
  else
    # Insert after schema_version if available, else prepend
    if grep -q '^schema_version:' "${yaml_file}"; then
      awk -v ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '
        BEGIN{printed=0}
        /^schema_version:/ && printed==0 { print; print "generated_at: \"" ts "\""; printed=1; next }
        { print }
      ' "${yaml_file}" > "${yaml_file}.tmp" && mv "${yaml_file}.tmp" "${yaml_file}"
    else
      { echo "generated_at: \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\""; cat "${yaml_file}"; } > "${yaml_file}.tmp" && mv "${yaml_file}.tmp" "${yaml_file}"
    fi
  fi

  # Ensure versions: exists
  if ! grep -q '^versions:' "${yaml_file}"; then
    echo "versions:" >> "${yaml_file}"
  fi

  # Remove existing blocks for selected versions
  # Rule: skip lines from '  "<ver>":' up to (but not including) the next '  "<other>":' or EOF.
  awk -v list="$(IFS=,; echo "${versions_to_replace[*]}")" '
    BEGIN {
      n=split(list, ver, ",")
      for(i=1;i<=n;i++) tgt[ver[i]]=1
      in_versions=0
      skip=0
    }
    /^versions:/ { in_versions=1; print; next }
    {
      if (in_versions==1) {
        # detect start of a version block: two spaces, quoted semver, colon
        if (match($0, /^[ ]{2}"[0-9]+\.[0-9]+\.[0-9]+":/)) {
          # extract the version key between quotes
          v=$0
          sub(/^[ ]{2}"/,"",v)
          sub(/":.*/,"",v)
          if (tgt[v]==1) {
            skip=1
            next
          } else {
            if (skip==1) {
              # we were skipping and hit a new block -> stop skipping, print this line
              skip=0
              print
              next
            }
          }
        }
        if (skip==1) {
          next
        }
        print
      } else {
        print
      }
    }
  ' "${yaml_file}" > "${yaml_file}.tmp" && mv "${yaml_file}.tmp" "${yaml_file}"

  # Append new blocks at end of file under versions:
  {
    echo ""
    for ver in "${versions_to_replace[@]}"; do
      echo "# updated: ${ver} ($(date -u +"%Y-%m-%dT%H:%M:%SZ"))"
      generate_yaml_block "${ver}" < ".opcli-${ver}.sha"
    done
  } >> "${yaml_file}"
}

# Git commit and optional PR creation
git_commit_and_maybe_pr() {
  local yaml_file="$1"
  local message="$2"
  local branch="$3"
  local open_pr="$4"

  require_cmd git
  if [ -n "${branch}" ]; then
    log "Switching to branch: ${branch}"
    if git rev-parse --verify "${branch}" >/dev/null 2>&1; then
      git checkout "${branch}"
    else
      git checkout -b "${branch}"
    fi
  fi

  git add "${yaml_file}"
  git commit -m "${message}" || log "No changes to commit."

  if [ "${open_pr}" = "true" ]; then
    if command -v gh >/dev/null 2>&1; then
      log "Opening PR via gh CLI..."
      gh pr create --fill --head "${branch}" || err "Failed to open PR with gh"
    else
      err "gh CLI not found; unable to open PR automatically."
      echo "Tip: Install GitHub CLI (gh) or open a PR manually."
    fi
  fi
}

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    -v|--version)
      [ $# -ge 2 ] || { err "Missing value for $1"; exit 1; }
      VERSIONS+=("${2#v}") # strip leading v if present
      shift 2
      ;;
    --latest)
      LATEST=true
      shift
      ;;
    -f|--file)
      [ $# -ge 2 ] || { err "Missing value for $1"; exit 1; }
      YAML_PATH="$2"
      shift 2
      ;;
    --update-file)
      DO_UPDATE_FILE=true
      shift
      ;;
    --commit)
      DO_UPDATE_FILE=true
      DO_COMMIT=true
      shift
      ;;
    --branch)
      [ $# -ge 2 ] || { err "Missing value for $1"; exit 1; }
      BRANCH_NAME="$2"
      shift 2
      ;;
    --open-pr)
      DO_UPDATE_FILE=true
      DO_COMMIT=true
      DO_OPEN_PR=true
      shift
      ;;
    -q|--quiet)
      QUIET=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# Ensure we have at least one version
if [ "${LATEST}" = "true" ]; then
  latest_ver="$(resolve_latest_version)"
  log "Resolved latest 1Password CLI version: ${latest_ver}"
  VERSIONS+=("${latest_ver}")
fi

if [ "${#VERSIONS[@]}" -eq 0 ]; then
  err "No versions specified. Use --latest or --version <X.Y.Z>."
  usage
  exit 1
fi

# Verify required tools
require_cmd curl
require_cmd unzip

# Compute SHA sets for each version and store intermediate results
for ver in "${VERSIONS[@]}"; do
  log "Computing checksums for version ${ver}..."
  compute_platform_shas "${ver}" > ".opcli-${ver}.sha"
  if [ ! -s ".opcli-${ver}.sha" ]; then
    err "No checksums produced for ${ver}; check connectivity or version correctness."
    exit 1
  fi
done

# If not updating file, print a complete snippet and exit
if [ "${DO_UPDATE_FILE}" = "false" ]; then
  cat <<EOF
# YAML snippet for 1password-cli-versions.yaml (append under 'versions:')
versions:
EOF
  for ver in "${VERSIONS[@]}"; do
    generate_yaml_block "${ver}" < ".opcli-${ver}.sha"
  done
  # Cleanup temp files
  rm -f .opcli-*.sha
  exit 0
fi

# Update or create YAML file
update_yaml_file "${YAML_PATH}" "${VERSIONS[@]}"

# Cleanup temp checksum files
rm -f .opcli-*.sha

log "Updated ${YAML_PATH}"

# Optionally commit and open PR
if [ "${DO_COMMIT}" = "true" ]; then
  msg="chore: update 1Password CLI versions ($(IFS=, ; echo "${VERSIONS[*]}"))"
  git_commit_and_maybe_pr "${YAML_PATH}" "${msg}" "${BRANCH_NAME}" "${DO_OPEN_PR}"
  log "Git operations completed."
fi

log "Done."
