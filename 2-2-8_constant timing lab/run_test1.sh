#!/usr/bin/env bash
set -u

echo "=================================================="
echo "실습 1: Valgrind secret-dependent flow 탐지"
echo "=================================================="

echo
echo "[1/2] 취약 구현 실행: 오류가 검출되어야 정상"
set +e
valgrind \
  --quiet \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  ./ct_branch_vuln
rc_vuln=$?
set -e

echo
if [ "$rc_vuln" -eq 99 ]; then
  echo "[PASS] 취약 구현에서 비밀 의존성이 검출되었습니다."
else
  echo "[WARN] 예상한 Valgrind 오류 코드가 나오지 않았습니다: $rc_vuln"
fi

echo
echo "[2/2] 수정 구현 실행: 오류가 없어야 정상"
set +e
valgrind \
  --quiet \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  ./ct_branch_safe
rc_safe=$?
set -e

echo
if [ "$rc_safe" -eq 0 ]; then
  echo "[PASS] 수정 구현에서 Valgrind 오류가 검출되지 않았습니다."
else
  echo "[FAIL] 수정 구현에서 오류가 검출되었습니다: $rc_safe"
  exit 1
fi
