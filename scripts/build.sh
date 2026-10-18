#!/usr/bin/env bash
# Build static binaries for every supported OS/CPU into dist/.
# Needs only Go: CGO is off, so cross-compiling works from any machine.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/app/app.go)
targets="linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"

mkdir -p dist
for t in $targets; do
  os=${t%/*}
  arch=${t#*/}
  ext=""
  [ "$os" = windows ] && ext=".exe"
  out="dist/log_anonimizer_${version}_${os}_${arch}${ext}"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/log_anonimizer
  echo "built $out"
done

cd dist
if command -v sha256sum >/dev/null; then
  sha256sum "log_anonimizer_${version}_"* > SHA256SUMS
else
  shasum -a 256 "log_anonimizer_${version}_"* > SHA256SUMS
fi
echo "checksums in dist/SHA256SUMS"
