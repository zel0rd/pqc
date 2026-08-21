# PQClean 기반 PQC 속도·코드 크기 비교 실습

## 1. 실습 목표

- ML-KEM의 KeyGen, Encaps, Decaps 측정
- ML-DSA의 KeyGen, Sign, Verify 측정
- 공개키·비밀키·암호문·서명 크기 확인
- 링크된 `.text` 코드 크기 비교
- 컴파일 옵션별 속도와 크기 trade-off 분석

## 2. 실습 0: 설치

```bash
chmod +x setup.sh run_easy.sh run_compare_flags.sh clean.sh
./setup.sh
```

자동으로 GCC, Clang, Python 환경, PQClean을 설치한다.

## 3. 실습 1: 전체 간편 실행

```bash
./run_easy.sh
```

대상:

```text
ML-KEM-512/768/1024
ML-DSA-44/65/87
```

결과 확인:

```bash
column -s, -t < results/results.csv | less -S
cat results/summary.md
ls -lh results/*.png
```

## 4. CSV 열 해석

| 열 | 의미 |
|---|---|
| operation | keypair, encaps, decaps, sign, verify |
| time_us | 연산 1회 평균 시간 |
| text_bytes | 링크된 `.text` |
| public_key_bytes | 공개키 크기 |
| secret_key_bytes | 비밀키 크기 |
| output_bytes | 암호문 또는 실제 서명 |
| message_or_shared_bytes | 메시지 또는 공유 비밀 |

## 5. 실습 2: ML-KEM-768

```bash
source .venv/bin/activate
python3 tools/lab.py one \
  --category kem \
  --algorithm ml-kem-768 \
  --compiler gcc \
  --opt O3 \
  --iterations 3000
column -s, -t < results/one_result.csv
```

프로그램은 `Encaps`와 `Decaps`의 공유 비밀이 같은지 먼저 검사한다.

## 6. 실습 3: ML-DSA-65

```bash
python3 tools/lab.py one \
  --category sign \
  --algorithm ml-dsa-65 \
  --compiler gcc \
  --opt O3 \
  --iterations 500 \
  --message-len 32
```

정상 서명 검증과 1비트 변조 메시지의 검증 실패를 자동 확인한다.

## 7. 실습 4: 메시지 길이

```bash
python3 tools/lab.py one --category sign --algorithm ml-dsa-65 --iterations 300 --message-len 32
cp results/one_result.csv results/mldsa_32B.csv

python3 tools/lab.py one --category sign --algorithm ml-dsa-65 --iterations 300 --message-len 1024
cp results/one_result.csv results/mldsa_1KB.csv

python3 tools/lab.py one --category sign --algorithm ml-dsa-65 --iterations 100 --message-len 1048576
cp results/one_result.csv results/mldsa_1MB.csv
```

질문:

- KeyGen은 메시지 길이에 영향을 받는가?
- Sign과 Verify에서 1MB 메시지의 해시 비용이 나타나는가?

## 8. 실습 5: 최적화 옵션

```bash
./run_compare_flags.sh
column -s, -t < results/flags_results.csv | less -S
```

비교 옵션:

```text
-O0, -O2, -O3, -Os, -O3 -march=native, -O3 -flto
```

질문:

- 가장 빠른 옵션은 무엇인가?
- `.text`가 가장 작은 옵션은 무엇인가?
- `-Os`의 크기 감소와 속도 저하를 비교하라.

## 9. 실습 6: GCC와 Clang

```bash
python3 tools/lab.py one --category kem --algorithm ml-kem-768 --compiler gcc --opt O3 --iterations 3000
cp results/one_result.csv results/gcc.csv

python3 tools/lab.py one --category kem --algorithm ml-kem-768 --compiler clang --opt O3 --iterations 3000
cp results/one_result.csv results/clang.csv
```

컴파일러에 따라 인라인, 루프 최적화, 레지스터 할당, 코드 크기가 달라질 수 있다.

## 10. 환경 기록

```bash
{
  date
  uname -a
  lscpu
  gcc --version
  clang --version
  git -C PQClean rev-parse HEAD
} > results/environment.txt
```

## 11. 제출물

```text
results/results.csv
results/summary.md
results/environment.txt
results/kem_performance.png
results/sign_performance.png
results/speed_vs_code_size.png
```

## 12. 분석 문제

1. 보안 파라미터 증가에 따라 각 연산시간이 어떻게 변하는가?
2. ML-KEM에서 가장 무거운 연산은 무엇인가?
3. ML-DSA의 Sign과 Verify 비용 차이를 설명하라.
4. 가장 작은 코드와 가장 빠른 코드가 같은가?
5. TLS KEM과 펌웨어 서명 검증에서 평가 가중치가 어떻게 다른가?
