# CBOM Risk Report

| Priority | Asset | Type | Location | Policy | Quantum-vulnerable | Action |
|---|---|---|---|---|---|---|
| High | RSA-2048 | algorithm | com/example/cbom/AuthService.java | migrate | true | PQC 또는 hybrid 전환 검토 |
| High | RSA-PKCS1-v1_5-SHA-256 | algorithm | com/example/cbom/AuthService.java | migrate | true | PQC 또는 hybrid 전환 검토 |
| High | EC-secp256r1 | algorithm | com/example/cbom/AuthService.java | migrate | true | PQC 또는 hybrid 전환 검토 |
| High | SHA-1 | algorithm | com/example/cbom/CryptoService.java | prohibited | false | 금지 알고리즘 제거 |
| Medium | AES | algorithm | com/example/cbom/CryptoService.java | review | false | 파라미터와 사용 맥락 검토 |
| Medium | PBKDF2-HMAC-SHA-256 | algorithm | com/example/cbom/PasswordService.java | review-parameters | false | 파라미터와 사용 맥락 검토 |
| Medium | TLS 1.2 | protocol | com/example/cbom/TlsConfig.java | review | depends-on-cipher-suite | 파라미터와 사용 맥락 검토 |
| Low | AES-256-GCM | algorithm | com/example/cbom/CryptoService.java | allowed | false | 현행 유지 및 모니터링 |
| Low | HMAC-SHA-256 | algorithm | com/example/cbom/CryptoService.java | allowed | false | 현행 유지 및 모니터링 |
| Low | PKCS#12 Keystore | related-crypto-material | com/example/cbom/TlsConfig.java | allowed | false | 현행 유지 및 모니터링 |

## Interpretation

- High: 즉시 제거 또는 PQC/hybrid 전환 계획 수립 대상
- Medium: 파라미터, 프로토콜 버전, 운영 맥락 검토 대상
- Low: 현행 유지 가능하나 지속적 모니터링 필요