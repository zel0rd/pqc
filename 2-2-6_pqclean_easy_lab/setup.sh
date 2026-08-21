#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "=== PQClean Easy Lab 설치 ==="
sudo apt-get update
sudo apt-get install -y git build-essential clang binutils python3 python3-venv python3-pip jq time
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pandas matplotlib pyyaml

if [ ! -d PQClean/.git ]; then
  git clone --depth 1 https://github.com/PQClean/PQClean.git PQClean
fi
git -C PQClean submodule update --init --recursive || true
python3 tools/lab.py doctor
echo
echo "설치 완료. 이제 ./run_easy.sh 를 실행하세요."
