CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -fno-omit-frame-pointer
LDFLAGS ?=

.PHONY: all setup check-deps test1 test2 all-tests clean help

setup:
	./setup.sh

check-deps:
	@command -v $(CC) >/dev/null 2>&1 || \
	  (echo "[오류] C 컴파일러가 없습니다. 먼저 'make setup'을 실행하세요."; exit 1)
	@command -v valgrind >/dev/null 2>&1 || \
	  (echo "[오류] Valgrind가 없습니다. 먼저 'make setup'을 실행하세요."; exit 1)
	@command -v objdump >/dev/null 2>&1 || \
	  (echo "[오류] objdump가 없습니다. 먼저 'make setup'을 실행하세요."; exit 1)
	@test -f /usr/include/valgrind/memcheck.h || \
	  (echo "[오류] valgrind/memcheck.h가 없습니다. 먼저 'make setup'을 실행하세요."; exit 1)

all: check-deps ct_branch_vuln ct_branch_safe kyberslash_demo

ct_branch_vuln: ct_branch_vuln.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

ct_branch_safe: ct_branch_safe.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

kyberslash_demo: kyberslash_demo.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test1: check-deps ct_branch_vuln ct_branch_safe
	./run_test1.sh

test2: check-deps kyberslash_demo
	./run_test2.sh

all-tests: test1 test2

clean:
	rm -f ct_branch_vuln ct_branch_safe kyberslash_demo
	rm -f kyberslash_demo.asm

help:
	@echo "make setup      # 필수 패키지 설치"
	@echo "make test1      # Valgrind branch/address 탐지"
	@echo "make test2      # KyberSlash형 division 탐지"
	@echo "make all-tests  # 전체 실습"
	@echo "make clean      # 생성 파일 삭제"
