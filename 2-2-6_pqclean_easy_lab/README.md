# PQClean Easy KEM/DSA Benchmark Lab

PQClean `clean` 구현으로 ML-KEM과 ML-DSA의 속도, 키·출력 크기, 링크 코드 크기를 자동 비교하는 Ubuntu 실습 패키지입니다.

## 학생이 입력할 명령

```bash
chmod +x setup.sh run_easy.sh run_compare_flags.sh clean.sh
./setup.sh
./run_easy.sh
```

결과:

```text
results/results.csv
results/summary.md
results/kem_performance.png
results/kem_code_size.png
results/sign_performance.png
results/sign_code_size.png
results/speed_vs_code_size.png
```

## 단일 알고리즘

```bash
source .venv/bin/activate
python3 tools/lab.py one --category kem --algorithm ml-kem-768 --iterations 3000
python3 tools/lab.py one --category sign --algorithm ml-dsa-65 --iterations 500
```

## 컴파일 옵션 비교

```bash
./run_compare_flags.sh
```

이 코드 크기는 알고리즘, 필요한 PQClean 공통 코드, 작은 측정 하네스를 포함한 링크 실행파일의 `.text`입니다. 동일 조건에서 상대 비교하는 교육용 지표입니다.
