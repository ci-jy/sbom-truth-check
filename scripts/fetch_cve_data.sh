#!/usr/bin/env bash
# Download the public inputs of `cpeinfer` into data/ (or $CPEINFER_DATA):
#   cvelistV5/cves/<year>/   CNA records (affected blocks), sparse + blobless checkout of CVEProject/cvelistV5
#   nvd/nvdcve-2.0-<year>.json.gz   NVD CVE 2.0 yearly feeds (NIST CPE configurations, vulnStatus)
#   nvd/nvdcpe-2.0.tar.gz           NVD CPE Dictionary 2.0 (chunked JSON)
# Everything stays compressed on disk; `python3 -m cpeinfer build` streams it into data/cpeinfer.jsonl.gz.
# Usage: scripts/fetch_cve_data.sh [YEAR ...]   (default: 2023 2024 2025)
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="${CPEINFER_DATA:-data}"
YEARS=("${@:-2023 2024 2025}")
read -r -a YEARS <<< "${YEARS[*]}"
mkdir -p "$DATA/nvd"

for y in "${YEARS[@]}"; do
  f="$DATA/nvd/nvdcve-2.0-$y.json.gz"
  curl -sSfL --retry 3 -z "$f" -o "$f" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
  echo "nvd feed $y: $(du -h "$f" | cut -f1)"
done
f="$DATA/nvd/nvdcpe-2.0.tar.gz"
curl -sSfL --retry 3 -z "$f" -o "$f" "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
echo "cpe dictionary: $(du -h "$f" | cut -f1)"

repo="$DATA/cvelistV5"
if [ ! -d "$repo/.git" ]; then
  git clone -q --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git "$repo"
fi
git -C "$repo" sparse-checkout set $(printf 'cves/%s ' "${YEARS[@]}")
git -C "$repo" pull -q --depth 1 || true
for y in "${YEARS[@]}"; do
  echo "cvelistV5 $y: $(find "$repo/cves/$y" -name 'CVE-*.json' | wc -l) records"
done
