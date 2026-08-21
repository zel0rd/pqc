# 발표자료: PQClean KEM·DSA 속도와 코드 크기 실습

## 1장. 제목
### PQClean 기반 PQC KEM·DSA 성능 비교 실습
- ML-KEM·ML-DSA clean 구현
- 연산별 속도와 링크 코드 크기
- 명령어 두 개로 결과 자동 생성

## 2장. 학습목표
- KEM의 KeyGen·Encaps·Decaps를 분리 측정한다.
- DSA의 KeyGen·Sign·Verify를 분리 측정한다.
- 키·출력·코드 크기와 실행시간을 함께 해석한다.

## 3장. 실습 흐름
```text
setup.sh → PQClean 다운로드 → run_easy.sh
→ 기능 검증 → 벤치마크 → CSV → 그래프
```

## 4장. 대상 알고리즘
- ML-KEM-512/768/1024
- ML-DSA-44/65/87
- `clean`, Ubuntu x86-64, GCC `-O3`

## 5장. KEM 구조
```text
KeyGen(pk,sk)
Encaps(pk) → ct, ss1
Decaps(sk,ct) → ss2
ss1 == ss2
```

## 6장. DSA 구조
```text
KeyGen(pk,sk)
Sign(sk,m) → sig
Verify(pk,m,sig) → 성공
m 변조 후 Verify → 실패
```

## 7장. 연산 분리의 필요성
- TLS 송신자: Encaps
- TLS 수신자: Decaps
- 서명 서버: Sign
- 대량 검증 장치: Verify
- 일회성 키: KeyGen

## 8장. 측정 지표
- `time_ns`, `time_us`
- 공개키·비밀키
- 암호문 또는 서명
- 링크 `.text`, `.data`, `.bss`

## 9장. 코드 크기 기준
```bash
size benchmark_binary
```
- `.text`: 실행 코드와 일부 상수
- 동일 하네스에서 상대 비교
- 공통 SHAKE·난수 코드 포함

## 10장. 설치
```bash
chmod +x setup.sh run_easy.sh run_compare_flags.sh clean.sh
./setup.sh
```

## 11장. 전체 실행
```bash
./run_easy.sh
```
- CSV
- 요약 Markdown
- KEM/DSA 속도 그래프
- 코드 크기 그래프
- 속도-크기 산점도

## 12장. 시간 측정 코드
```c
clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
```
연산 1회 시간 = 전체 반복시간 / 반복 횟수

## 13장. Warm-up
- KEM 5회
- DSA 3회
- 기능 검증
- 초기 cache와 page fault 영향 완화

## 14장. easy preset
- KEM 500회
- DSA 100회
- 수업 중 빠른 실행
- 심화 분석은 반복 횟수 증가

## 15장. CSV 구조
| 항목 | 의미 |
|---|---|
| operation | 측정 연산 |
| time_us | 평균 μs/op |
| text_bytes | 링크 코드 |
| output_bytes | 암호문·서명 |
| pqclean_commit | 재현성 정보 |

## 16장. KEM 그래프 해석
- 보안 레벨 증가와 시간
- KeyGen·Encaps·Decaps 비대칭
- 키와 암호문 크기 증가
- 사용 시나리오별 병목

## 17장. DSA 그래프 해석
- Sign과 Verify 차이
- KeyGen 비중
- 보안 레벨 증가 비용
- 대량 서명과 대량 검증의 차이

## 18장. 단일 KEM 실행
```bash
python3 tools/lab.py one \
 --category kem --algorithm ml-kem-768 \
 --iterations 3000
```

## 19장. 단일 DSA 실행
```bash
python3 tools/lab.py one \
 --category sign --algorithm ml-dsa-65 \
 --iterations 500 --message-len 32
```

## 20장. 메시지 길이 실험
- 32 B
- 1 KB
- 1 MB
- KeyGen 불변
- Sign·Verify에서 해싱 비용 관찰

## 21장. 최적화 옵션
```text
-O0 / -O2 / -O3 / -Os
-march=native / -flto
```

## 22장. `-march=native`
장점:
- 현재 CPU 기능 활용
- 자동 벡터화 가능

한계:
- 다른 PC 재현성 저하
- 배포 이식성 저하

## 23장. GCC와 Clang
- 인라인
- 루프 전개
- 레지스터 할당
- instruction selection
- `.text` 크기

## 24장. 속도-코드 크기 산점도
```text
X축: .text KiB
Y축: Encaps 또는 Sign μs
```
왼쪽 아래가 작고 빠른 영역이다.

## 25장. 공정한 측정 조건
- 동일 CPU·OS
- 동일 compiler·flags
- 동일 PQClean commit
- 동일 메시지와 반복 횟수
- 동일 `clean` 구현

## 26장. 측정 한계
- OS scheduling
- CPU frequency scaling
- 평균 중심 간편 실습
- 하네스 포함 링크 크기
- PC 간 절대 수치 비교 주의

## 27장. 논문 수준 확장
- CPU affinity
- governor 고정
- median·p95·p99
- 여러 trial
- `perf stat`
- confidence interval

## 28장. 학습정리
- PQC는 연산별로 평가한다.
- 속도·통신량·코드 크기는 별도 지표다.
- 컴파일 옵션도 성능을 바꾼다.
- 하나의 알고리즘이 모든 환경에서 최선은 아니다.
