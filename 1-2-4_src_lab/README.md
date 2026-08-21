# crypto-c-static-lab

C/OpenSSL 기반 소스코드 정적 분석 암호자산 식별 실습입니다.

## 설치

```bash
sudo apt update
sudo apt install -y build-essential clang gcc make openssl libssl-dev python3 python3-pip ripgrep jq tree
python3 -m pip install --user semgrep
export PATH="$HOME/.local/bin:$PATH"
```

## 실행

```bash
chmod +x run_c_lab.sh scripts/*.sh scripts/*.py
bash run_c_lab.sh
```

## 결과

```text
results/c_crypto_findings.csv
results/c_crypto_findings.json
results/openssl_pqc_check.txt
results/cert_algorithms.txt
```

## 실습 포함 항목

- 취약 암호 API 탐지: MD5, SHA-1, AES-ECB
- RSA/ECC API 탐지: RSA_generate_key_ex, EC_KEY_new_by_curve_name
- OpenSSL PQC 지원 여부 확인
- 인증서 공개키/서명 알고리즘 추출
- P-256 파라미터 기반 ECC 구현 식별
- RSA 공개지수 65537 기반 RSA 사용 추정

## Added lab: AES/RSA/ECC key-length detection

Additional examples are included:

- `vulnerable-c/openssl_aes_key_lengths.c`: AES-128/192/256 detection from `EVP_aes_<bits>_<mode>()` and key buffer size.
- `vulnerable-c/openssl_rsa_key_lengths.c`: RSA-1024/2048/3072/4096 detection from `RSA_generate_key_ex(..., bits, ...)`.
- `vulnerable-c/openssl_ecc_key_lengths.c`: ECC key length detection from OpenSSL curve NIDs such as `NID_X9_62_prime256v1`, `NID_secp384r1`, and `NID_secp521r1`.

Run:

```bash
python3 scripts/key_length_inventory.py .
```

Outputs:

```text
results/key_length_inventory.csv
results/key_length_inventory.json
```
