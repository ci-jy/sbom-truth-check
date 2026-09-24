#!/usr/bin/env bash
# Download the pinned manifest + lockfile of every corpus repository into corpus/<name>/src.
# Maven projects additionally get src/dependency-tree.txt from `mvn dependency:tree` (the ground-truth input).
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
M2="${MAVEN_REPO:-${TMPDIR:-/tmp}/m2-repository}"

python3 - <<'PY' > "$WORK/list.tsv"
import json
for r in json.load(open("corpus/repos.json")):
    print(r["name"], r["repo"], r["commit"], r["ecosystem"], sep="\t")
PY

while IFS=$'\t' read -r name repo commit eco; do
  dest="corpus/$name/src"
  mkdir -p "$dest"
  case "$eco" in
    npm)    files="package.json package-lock.json" ;;
    poetry) files="pyproject.toml poetry.lock" ;;
    maven)  files="pom.xml" ;;
  esac
  for f in $files; do
    curl -sSfL "https://raw.githubusercontent.com/$repo/$commit/$f" -o "$dest/$f"
  done
  if [ "$eco" = maven ]; then
    (cd "$dest" && MAVEN_OPTS="-Xmx512m" mvn -q -B -Dmaven.repo.local="$M2" \
        dependency:tree -DoutputFile="$PWD/dependency-tree.txt" -DappendOutput=false >/dev/null)
  fi
  echo "fetched $name ($eco @ ${commit:0:12})"
done < "$WORK/list.tsv"
