#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build results
mkdir -p build results
echo "빌드 및 결과 파일을 삭제했습니다."
