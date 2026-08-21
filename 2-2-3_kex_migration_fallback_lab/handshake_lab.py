#!/usr/bin/env python3
"""
Certificate-less key-exchange migration/fallback lab.
This is NOT TLS and NOT production crypto. It models only the handshake negotiation flow:
ClientHello -> ServerHello -> key exchange -> shared secret -> fallback/retry.

Modes:
  x25519      : classical ECDH using cryptography package
  toy-pqc     : educational KEM-like interface using HMAC/SHA256, NOT secure
  hybrid      : X25519 + toy-pqc combined with HKDF
"""
import argparse, base64, hashlib, hmac, os, sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("[!] Missing dependency: pip install cryptography", file=sys.stderr)
    sys.exit(1)

SUPPORTED = ["hybrid", "toy-pqc", "x25519"]
TOY_PQC_PK_LEN = 1184      # ML-KEM-768 public-key-like size, for packet-size teaching
TOY_PQC_CT_LEN = 1088      # ML-KEM-768 ciphertext-like size
X25519_PK_LEN = 32


def b64(b: bytes, n=18) -> str:
    return base64.b64encode(b).decode()[:n] + "..."


def hkdf(label: bytes, *parts: bytes, out_len=32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=out_len, salt=None, info=label).derive(b"".join(parts))


class ToyPQCServerKEM:
    """Educational KEM-like server key. Decapsulation is simulated by HMAC over ciphertext."""
    def __init__(self):
        self.sk = os.urandom(32)
        # long public key to show PQC packet-size impact
        self.pk = hkdf(b"toy-pqc-pk", self.sk, out_len=TOY_PQC_PK_LEN)

    def encapsulate_for_client_demo(self, client_nonce: bytes) -> Tuple[bytes, bytes]:
        # In a real KEM, the client encapsulates to server public key. For a two-process-free lab,
        # server computes both sides deterministically to demonstrate matching secrets.
        ct_core = hkdf(b"toy-pqc-ct", self.pk, client_nonce, out_len=32)
        ct = ct_core + os.urandom(TOY_PQC_CT_LEN - len(ct_core))
        ss = hmac.new(self.sk, ct_core, hashlib.sha256).digest()
        return ct, ss

    def decapsulate(self, ct: bytes) -> bytes:
        ct_core = ct[:32]
        return hmac.new(self.sk, ct_core, hashlib.sha256).digest()


@dataclass
class Policy:
    require_pqc: bool = False
    allow_classic_fallback: bool = True
    max_handshake_bytes: int = 4096


@dataclass
class Result:
    success: bool
    selected: Optional[str]
    fallback_used: bool
    reason: str
    bytes_estimate: int
    secret_preview: Optional[str] = None


class Client:
    def __init__(self, offers: List[str], policy: Policy, downgrade_strip: bool = False):
        self.offers = offers
        self.policy = policy
        self.downgrade_strip = downgrade_strip

    def client_hello(self) -> List[str]:
        offers = list(self.offers)
        if self.downgrade_strip:
            offers = [x for x in offers if x == "x25519"]
            print("[attacker] stripped PQC/hybrid offers from ClientHello")
        print(f"[client] ClientHello.key_exchange = {offers}")
        return offers


class Server:
    def __init__(self, supports: List[str]):
        self.supports = supports
        self.kem = ToyPQCServerKEM()

    def select(self, offers: List[str]) -> Optional[str]:
        for mode in offers:
            if mode in self.supports:
                return mode
        return None


def estimate_bytes(mode: str) -> int:
    base = 160  # toy header/transcript overhead
    if mode == "x25519":
        return base + 2 * X25519_PK_LEN
    if mode == "toy-pqc":
        return base + TOY_PQC_PK_LEN + TOY_PQC_CT_LEN
    if mode == "hybrid":
        return base + 2 * X25519_PK_LEN + TOY_PQC_PK_LEN + TOY_PQC_CT_LEN
    return base


def run_handshake(client: Client, server: Server, retry_classic_on_size: bool = False) -> Result:
    fallback_used = False
    offers = client.client_hello()
    selected = server.select(offers)
    if not selected:
        return Result(False, None, False, "no mutually supported key exchange", 0)

    print(f"[server] ServerHello.selected = {selected}")
    bytes_est = estimate_bytes(selected)
    print(f"[wire] estimated handshake bytes = {bytes_est}, limit = {client.policy.max_handshake_bytes}")

    if bytes_est > client.policy.max_handshake_bytes:
        print(f"[network] packet budget exceeded by {bytes_est - client.policy.max_handshake_bytes} bytes")
        if retry_classic_on_size and "x25519" in client.offers and "x25519" in server.supports:
            selected = "x25519"
            fallback_used = True
            bytes_est = estimate_bytes(selected)
            print("[client] retrying with fallback x25519")
        else:
            return Result(False, selected, False, "handshake too large; no fallback retry", bytes_est)

    if client.policy.require_pqc and selected == "x25519":
        return Result(False, selected, fallback_used, "policy requires PQC/hybrid; classic fallback rejected", bytes_est)
    if selected == "x25519" and not client.policy.allow_classic_fallback:
        return Result(False, selected, fallback_used, "classic fallback disabled by policy", bytes_est)

    transcript = b"ClientHello|ServerHello|" + selected.encode()

    if selected in ("x25519", "hybrid"):
        c_sk = x25519.X25519PrivateKey.generate()
        s_sk = x25519.X25519PrivateKey.generate()
        c_pk = c_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        s_pk = s_sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        c_ecdh = c_sk.exchange(x25519.X25519PublicKey.from_public_bytes(s_pk))
        s_ecdh = s_sk.exchange(x25519.X25519PublicKey.from_public_bytes(c_pk))
        assert c_ecdh == s_ecdh
        print(f"[x25519] shared = {b64(c_ecdh)}")
    else:
        c_ecdh = b""

    if selected in ("toy-pqc", "hybrid"):
        nonce = os.urandom(32)
        ct, c_pqc = server.kem.encapsulate_for_client_demo(nonce)
        s_pqc = server.kem.decapsulate(ct)
        assert c_pqc == s_pqc
        print(f"[toy-pqc] pk_len={len(server.kem.pk)}, ct_len={len(ct)}, shared={b64(c_pqc)}")
    else:
        c_pqc = b""

    master = hkdf(b"demo-handshake-secret", transcript, c_ecdh, c_pqc)
    print(f"[both] handshake_secret = {b64(master)}")
    return Result(True, selected, fallback_used, "ok", bytes_est, b64(master))


def parse_csv(s: str) -> List[str]:
    out = [x.strip() for x in s.split(",") if x.strip()]
    for x in out:
        if x not in SUPPORTED:
            raise SystemExit(f"unsupported mode: {x}; choose from {SUPPORTED}")
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--client-offers", default="hybrid,toy-pqc,x25519")
    p.add_argument("--server-supports", default="hybrid,toy-pqc,x25519")
    p.add_argument("--max-bytes", type=int, default=4096)
    p.add_argument("--require-pqc", action="store_true")
    p.add_argument("--no-classic-fallback", action="store_true")
    p.add_argument("--retry-classic-on-size", action="store_true")
    p.add_argument("--downgrade-strip", action="store_true")
    args = p.parse_args()

    pol = Policy(require_pqc=args.require_pqc,
                 allow_classic_fallback=not args.no_classic_fallback,
                 max_handshake_bytes=args.max_bytes)
    c = Client(parse_csv(args.client_offers), pol, args.downgrade_strip)
    s = Server(parse_csv(args.server_supports))
    r = run_handshake(c, s, retry_classic_on_size=args.retry_classic_on_size)
    status = "SUCCESS" if r.success else "FAIL"
    fb = "yes" if r.fallback_used else "no"
    print(f"\n[result] {status} selected={r.selected} fallback={fb} reason={r.reason}")
    sys.exit(0 if r.success else 2)


if __name__ == "__main__":
    main()
