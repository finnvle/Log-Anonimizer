#!/usr/bin/env bash
# Rebuild every file in examples/ from sample.log (fictional data) and check
# that both maps restore it exactly. Run after changing the detectors.
set -euo pipefail
cd "$(dirname "$0")"

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
go build -o "$bin/la" ../cmd/log_anonimizer
la="$bin/la"

# plain map: sample.anonmap (profile.yaml has encrypt_map: false)
"$la" -q -f -a sample.log -p profile.yaml
"$la" -f -d sample.anon.log >/dev/null
cmp sample.log sample.restored.log
"$la" -show sample.anon.log > show.txt

# the same map, encrypted with the passphrase example-passphrase. Made in a
# temporary folder with the same file names, so the map records the same paths.
mkdir "$bin/enc"
cp sample.log "$bin/enc/"
sed 's/^encrypt_map:.*/encrypt_map: true/' profile.yaml > "$bin/enc/profile.yaml"
(cd "$bin/enc" && LOGANON_PASSPHRASE=example-passphrase "$la" -q -a sample.log -p profile.yaml \
  -m sample.encrypted.anonmap)
cmp "$bin/enc/sample.anon.log" sample.anon.log # same tokens as the plain map
mv "$bin/enc/sample.encrypted.anonmap" .
LOGANON_PASSPHRASE=example-passphrase "$la" -d sample.anon.log -m sample.encrypted.anonmap \
  -o "$bin/restored.log" >/dev/null
cmp "$bin/restored.log" sample.log

echo "examples regenerated"
