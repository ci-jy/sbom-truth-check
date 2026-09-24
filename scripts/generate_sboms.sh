#!/usr/bin/env bash
# Regenerate every corpus SBOM with the pinned generators, using each tool's default settings
# (what a vendor running the tool out of the box would ship). Outputs go to corpus/<name>/sboms/.
#   cyclonedx-npm  (npm projects, CycloneDX 1.6, --package-lock-only)
#   cyclonedx-py   (Poetry projects, CycloneDX 1.6)
#   syft           (all projects, CycloneDX 1.6 + SPDX 2.3)
#   trivy          (all projects, CycloneDX + SPDX 2.3)
# A generator that crashes leaves corpus/<name>/sboms/<tool>.error.txt with its message instead of an SBOM.
# Tool locations can be overridden with SYFT, TRIVY, CYCLONEDX_PY; cyclonedx-npm runs through npx.
set -euo pipefail
cd "$(dirname "$0")/.."
SYFT="${SYFT:-syft}"
TRIVY="${TRIVY:-trivy}"
CYCLONEDX_PY="${CYCLONEDX_PY:-cyclonedx-py}"
CDX_NPM_VERSION="6.0.1"
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${TMPDIR:-/tmp}/trivy-cache}"
export SYFT_CHECK_FOR_APP_UPDATE=false

run() {  # run <tool-label> <command...>; keep going if the generator fails
  local label="$1"; shift
  if ! "$@" </dev/null >"$WORKLOG" 2>&1; then
    tail -n 5 "$WORKLOG" > "$out/$label.error.txt"
    find "$out" -type f -empty -delete
  fi
}
WORKLOG="$(mktemp)"
trap 'rm -f "$WORKLOG"' EXIT

python3 -c 'import json; [print(r["name"], r["ecosystem"]) for r in json.load(open("corpus/repos.json"))]' |
while read -r name eco; do
  src="corpus/$name/src"
  out="corpus/$name/sboms"
  rm -rf "$out"; mkdir -p "$out"
  case "$eco" in
    npm)
      run cyclonedx-npm npx --yes "@cyclonedx/cyclonedx-npm@$CDX_NPM_VERSION" --package-lock-only \
          --spec-version 1.6 --output-format JSON --output-file "$out/cyclonedx-npm.cdx.json" "$src/package.json" ;;
    poetry)
      run cyclonedx-py "$CYCLONEDX_PY" poetry --sv 1.6 --of JSON -o "$out/cyclonedx-py.cdx.json" "$src" ;;
  esac
  run syft "$SYFT" -q "dir:$src" -o "cyclonedx-json@1.6=$out/syft.cdx.json" -o "spdx-json@2.3=$out/syft.spdx.json"
  run trivy "$TRIVY" -q fs --format cyclonedx --output "$out/trivy.cdx.json" "$src"
  run trivy-spdx "$TRIVY" -q fs --format spdx-json --output "$out/trivy.spdx.json" "$src"
  echo "generated $name: $(ls "$out" | tr '\n' ' ')"
done
