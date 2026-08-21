#!/usr/bin/env bash
set -e

echo "[설치] build-essential, valgrind, binutils"
sudo apt update
sudo apt install -y build-essential valgrind binutils

echo
echo "[확인]"
gcc --version | head -n 1
valgrind --version
objdump --version | head -n 1

echo
echo "[완료] 다음 명령을 실행하세요."
echo "make test1"
echo "make test2"
