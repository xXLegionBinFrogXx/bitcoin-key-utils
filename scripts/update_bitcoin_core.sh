#!/usr/bin/env bash
set -euo pipefail

# --- Configurable bits --------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/bitcoin/bitcoin.git}"
# You can set BTC_TAG or BTC_COMMIT via env. If both set, COMMIT wins.
BTC_TAG="${BTC_TAG:-v28.1}"         # example tag
BTC_COMMIT="${BTC_COMMIT:-}"        # optional: exact commit hash

# project root = repo root (adjust if you run from elsewhere)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${ROOT_DIR}/external/bitcoin-core"
mkdir -p "$DEST_DIR"

WORK_DIR="${ROOT_DIR}/.tmp/bitcoin-core-src"

# The exact files project relays on (relative to the Bitcoin Core repo root)
FILES=(
  # Source files (5 files needed by KeyManager)
  "src/base58.cpp"
  "src/bech32.cpp"
  "src/crypto/sha256.cpp"
  "src/crypto/sha256_sse4.cpp"
  "src/crypto/ripemd160.cpp"
  "src/crypto/hex_base.cpp"
  "src/util/strencodings.cpp"
  
  # Header files - Direct includes (5 files)
  "src/base58.h"
  "src/bech32.h"
  "src/crypto/sha256.h"
  "src/crypto/ripemd160.h"
  "src/util/strencodings.h"
  
  # Header files - Additional dependencies (5 files)
  "src/util/vector.h"
  "src/hash.h"
  "src/uint256.h"
  "src/prevector.h"
  "src/serialize.h"
  
  # Header files - Transitive dependencies (9 files)
  "src/span.h"
  "src/crypto/hex_base.h"
  "src/util/string.h"
  "src/crypto/common.h"
  "src/compat/endian.h"
  "src/compat/byteswap.h"
  "src/compat/assumptions.h"
  "src/compat/cpuid.h"
  "src/attributes.h"
  
  "COPYING"    # MIT license
)

# --- Helpers -----------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }

# --- Fetch source -------------------------------------------------------------
echo ">> Preparing work dir: ${WORK_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

echo ">> Shallow cloning ${REPO_URL}"
git -c advice.detachedHead=false clone --filter=blob:none --depth 1 "${REPO_URL}" "${WORK_DIR}"

pushd "${WORK_DIR}" >/dev/null

if [[ -n "${BTC_COMMIT}" ]]; then
  echo ">> Checking out commit ${BTC_COMMIT}"
  git fetch --depth 1 origin "${BTC_COMMIT}"
  git checkout --detach "${BTC_COMMIT}"
else
  echo ">> Checking out tag ${BTC_TAG}"
  git fetch --tags --depth 1 origin "refs/tags/${BTC_TAG}:refs/tags/${BTC_TAG}" || true
  git checkout --detach "tags/${BTC_TAG}"
fi

COMMIT_HASH="$(git rev-parse --short HEAD)"
echo ">> Using Bitcoin Core @ ${COMMIT_HASH}"

popd >/dev/null

# --- Copy curated files -------------------------------------------------------
echo ">> Updating ${DEST_DIR}"
# Keep your local CMakeLists.txt; refresh everything else we manage.
# We'll place files under the same relative structure expected by your CMake.
find "${DEST_DIR}" -mindepth 1 -not -name 'CMakeLists.txt' -exec rm -rf {} +

for f in "${FILES[@]}"; do
  src="${WORK_DIR}/${f}"
  # map 'src/... -> DEST_DIR/...'
  # COPYING stays at DEST_DIR/COPYING
  rel="${f#src/}"
  if [[ "${f}" == "COPYING" ]]; then
    rel="COPYING"
  fi
  out="${DEST_DIR}/${rel}"
  mkdir -p "$(dirname "${out}")"
  [[ -f "${src}" ]] || die "File not found in repo: ${f}"
  cp "${src}" "${out}"
done

# --- Record provenance --------------------------------------------------------
echo "${COMMIT_HASH}" > "${DEST_DIR}/VERSION.txt"

cat > "${DEST_DIR}/README.local.txt" <<EOF
This folder contains a *curated* subset of files from Bitcoin Core.

Upstream repository : ${REPO_URL}
Pinned revision     : ${COMMIT_HASH}
Updated by          : scripts/update_bitcoin_core.sh

Only the files listed in that script are synced here.
License: see COPYING (MIT).
EOF


# --- Cleanup work dir ---------------------------------------------------------
echo ">> Cleaning up ${WORK_DIR}"
rm -rf "${WORK_DIR}"

echo ">> Done. Synced files from Bitcoin Core @ ${COMMIT_HASH}"


