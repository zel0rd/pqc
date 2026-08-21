#!/usr/bin/env bash
set -u

echo "=================================================="
echo "실습 2: KyberSlash형 division 누설"
echo "=================================================="

echo
echo "[1/3] 일반 Valgrind 실행"
set +e
valgrind \
  --quiet \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  ./kyberslash_demo
rc=$?
set -e

echo
if [ "$rc" -eq 0 ]; then
  echo "[관찰] 일반 Valgrind가 secret-dependent division을 경고하지 않았습니다."
else
  echo "[관찰] Valgrind 반환 코드: $rc"
fi

echo
echo "[2/3] 바이너리의 division 명령어 검사"
objdump -d ./kyberslash_demo > kyberslash_demo.asm

if grep -Eiq '\b(div|idiv|udiv|sdiv)[a-z]*\b' kyberslash_demo.asm; then
  echo "[PASS] div/idiv 계열 명령어가 확인되었습니다."
  grep -Ei '\b(div|idiv|udiv|sdiv)[a-z]*\b' kyberslash_demo.asm | head -n 10
else
  echo "[WARN] div 명령어를 찾지 못했습니다."
  echo "컴파일러/아키텍처에 따라 명령어 형태가 다를 수 있습니다."
fi

echo
echo "[3/3] Valgrind 밖에서 시간 측정"
./kyberslash_demo

echo
echo "[핵심 결론]"
echo "Valgrind PASS만으로 KyberSlash형 누설이 없다고 판단할 수 없습니다."
