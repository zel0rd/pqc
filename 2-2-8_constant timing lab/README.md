# PQC Constant-Time 실습 2종

Ubuntu 환경에서 학생들이 명령어만 입력하여 결과를 확인할 수 있도록 구성한 C 언어 실습입니다.

## 0. 준비

```bash
make setup
```

## 실습 1: Valgrind로 비밀 의존 분기/메모리 접근 탐지

```bash
make test1
```

예상 결과:

- 취약 구현: Valgrind 오류 발생
- 안전 구현: Valgrind 오류 없음

## 실습 2: KyberSlash형 비밀 의존 나눗셈 탐지

```bash
make test2
```

예상 결과:

- 일반 Valgrind는 비밀값이 나눗셈 피연산자로 사용되어도 경고하지 않을 수 있음
- 정적 바이너리 검사에서 `div`/`idiv` 명령어 확인
- 반복 측정을 통해 입력 클래스별 실행시간 차이 비교
- reciprocal multiplication 기반 수정 구현과 비교

## 전체 실행

```bash
make all-tests
```

## 정리

```bash
make clean
```

> 주의: 실습 2의 실제 시간 차이는 CPU, 컴파일러, 가상머신, 전원관리 상태에 따라 달라질 수 있습니다.
> 이 실습은 KyberSlash의 핵심 원리인 "비밀값이 가변 지연 가능 명령어의 피연산자가 되는 문제"를 교육하기 위한 최소 예제입니다.
