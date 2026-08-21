#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, platform, re, shutil, subprocess, sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PQCLEAN, BUILD, RESULTS = ROOT/"PQClean", ROOT/"build", ROOT/"results"
KEMS = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]
SIGNS = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]

COMMON_MAP = {
    "randombytes.h": ["randombytes.c"],
    "fips202.h": ["fips202.c"],
    "sha2.h": ["sha2.c"],
    "aes.h": ["aes.c", "aes_c.c"],
    "sp800-185.h": ["sp800-185.c", "fips202.c"],
    "nistseedexpander.h": ["nistseedexpander.c", "aes.c", "aes_c.c"],
}

@dataclass
class Api:
    pk: str
    sk: str
    out: str
    extra: str
    keypair: str
    op1: str
    op2: str

def capture(cmd):
    return subprocess.check_output([str(x) for x in cmd], text=True).strip()

def execute(cmd):
    print("+", " ".join(str(x) for x in cmd))
    subprocess.run([str(x) for x in cmd], check=True)

def doctor():
    print("OS:", platform.platform())
    print("PQClean:", "OK" if PQCLEAN.exists() else "없음")
    for t in ["gcc","clang","size","git","python3"]:
        print(f"{t:7}:", shutil.which(t) or "없음")
    if not PQCLEAN.exists():
        raise SystemExit("./setup.sh를 먼저 실행하세요.")
    for base, names in [("crypto_kem", KEMS), ("crypto_sign", SIGNS)]:
        for name in names:
            p = PQCLEAN/base/name/"clean"/"api.h"
            print(f"{base}/{name}/clean:", "OK" if p.exists() else "없음")

def parse_api(impl: Path, category: str) -> Api:
    text = (impl/"api.h").read_text(errors="ignore")
    macros = re.findall(r"^\s*#define\s+([A-Za-z0-9_]+)\s+[^\s/]+", text, re.M)
    funcs = re.findall(r"\bint\s+([A-Za-z0-9_]+crypto_[A-Za-z0-9_]+)\s*\(", text)
    def m(s):
        x = [v for v in macros if v.endswith(s)]
        if not x: raise RuntimeError(f"{s} 매크로 탐색 실패")
        return x[0]
    def f(s):
        x = [v for v in funcs if v.endswith(s)]
        if not x: raise RuntimeError(f"{s} 함수 탐색 실패")
        return x[0]
    if category == "kem":
        return Api(m("CRYPTO_PUBLICKEYBYTES"), m("CRYPTO_SECRETKEYBYTES"),
                   m("CRYPTO_CIPHERTEXTBYTES"), m("CRYPTO_BYTES"),
                   f("crypto_kem_keypair"), f("crypto_kem_enc"), f("crypto_kem_dec"))
    return Api(m("CRYPTO_PUBLICKEYBYTES"), m("CRYPTO_SECRETKEYBYTES"),
               m("CRYPTO_BYTES"), m("CRYPTO_BYTES"),
               f("crypto_sign_keypair"), f("crypto_sign_signature"), f("crypto_sign_verify"))

def common_sources(impl_sources):
    includes = set()
    for p in impl_sources:
        includes.update(re.findall(r'#include\s+"([^"]+)"', p.read_text(errors="ignore")))
    names = ["randombytes.c"]
    for h, srcs in COMMON_MAP.items():
        if h in includes: names += srcs
    result = []
    for name in dict.fromkeys(names):
        p = PQCLEAN/"common"/name
        if p.exists(): result.append(p)
    return result

KEM_C = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))exit(2);return(uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;}
static void row(const char*n,size_t k,uint64_t e){printf("%s,%zu,%.3f\n",n,k,(double)e/k);}
int main(int argc,char**argv){
 size_t n=argc>1?strtoull(argv[1],0,10):500;if(!n)n=1;
 uint8_t*pk=malloc(PK);uint8_t*sk=malloc(SK);uint8_t*ct=malloc(OUT);uint8_t*a=malloc(EXTRA);uint8_t*b=malloc(EXTRA);
 if(!pk||!sk||!ct||!a||!b)return 2;
 for(size_t i=0;i<5;i++){if(KEYPAIR(pk,sk)||OP1(ct,a,pk)||OP2(b,ct,sk))return 3;}
 if(memcmp(a,b,EXTRA))return 4;
 uint64_t s=now_ns();for(size_t i=0;i<n;i++)if(KEYPAIR(pk,sk))return 3;uint64_t e=now_ns();row("keypair",n,e-s);
 s=now_ns();for(size_t i=0;i<n;i++)if(OP1(ct,a,pk))return 3;e=now_ns();row("encaps",n,e-s);
 s=now_ns();for(size_t i=0;i<n;i++)if(OP2(b,ct,sk))return 3;e=now_ns();row("decaps",n,e-s);
 if(memcmp(a,b,EXTRA))return 4;
 printf("sizes,%d,%d,%d,%d\n",PK,SK,OUT,EXTRA);
 free(pk);free(sk);free(ct);free(a);free(b);return 0;
}
'''

SIGN_C = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "api.h"
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))exit(2);return(uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;}
static void row(const char*n,size_t k,uint64_t e){printf("%s,%zu,%.3f\n",n,k,(double)e/k);}
int main(int argc,char**argv){
 size_t n=argc>1?strtoull(argv[1],0,10):100;if(!n)n=1;size_t ml=argc>2?strtoull(argv[2],0,10):32;if(!ml)ml=1;
 uint8_t*pk=malloc(PK);uint8_t*sk=malloc(SK);uint8_t*sig=malloc(OUT);uint8_t*m=malloc(ml);size_t sl=0;
 if(!pk||!sk||!sig||!m)return 2;for(size_t i=0;i<ml;i++)m[i]=(uint8_t)i;
 for(size_t i=0;i<3;i++){if(KEYPAIR(pk,sk)||OP1(sig,&sl,m,ml,sk)||OP2(sig,sl,m,ml,pk))return 3;}
 uint64_t s=now_ns();for(size_t i=0;i<n;i++)if(KEYPAIR(pk,sk))return 3;uint64_t e=now_ns();row("keypair",n,e-s);
 s=now_ns();for(size_t i=0;i<n;i++)if(OP1(sig,&sl,m,ml,sk))return 3;e=now_ns();row("sign",n,e-s);
 s=now_ns();for(size_t i=0;i<n;i++)if(OP2(sig,sl,m,ml,pk))return 3;e=now_ns();row("verify",n,e-s);
 m[0]^=1;if(OP2(sig,sl,m,ml,pk)==0)return 4;
 printf("sizes,%d,%d,%zu,%zu\n",PK,SK,sl,ml);
 free(pk);free(sk);free(sig);free(m);return 0;
}
'''

def flags(opt):
    return {"O0":["-O0"],"O2":["-O2"],"O3":["-O3"],"Os":["-Os"],
            "native":["-O3","-march=native"],"lto":["-O3","-flto"]}[opt]

def harness(category, api):
    t = KEM_C if category == "kem" else SIGN_C
    vals = {"PK":api.pk,"SK":api.sk,"OUT":api.out,"EXTRA":api.extra,
            "KEYPAIR":api.keypair,"OP1":api.op1,"OP2":api.op2}
    for k in sorted(vals, key=len, reverse=True):
        t = re.sub(rf"\b{k}\b", vals[k], t)
    return t

def build(category, algorithm, compiler, opt):
    base = "crypto_kem" if category=="kem" else "crypto_sign"
    impl = PQCLEAN/base/algorithm/"clean"
    if not impl.exists(): raise FileNotFoundError(impl)
    api = parse_api(impl, category)
    outdir = BUILD/f"{category}_{algorithm}_{compiler}_{opt}"
    shutil.rmtree(outdir, ignore_errors=True);outdir.mkdir(parents=True)
    cfile=outdir/"bench.c";cfile.write_text(harness(category,api))
    implsrc=sorted(impl.glob("*.c"));commons=common_sources(implsrc)
    binary=outdir/"bench"
    cmd=[compiler,"-std=c99","-Wall","-Wextra",*flags(opt),
         "-ffunction-sections","-fdata-sections",f"-I{impl}",f"-I{PQCLEAN/'common'}",
         cfile,*implsrc,*commons,"-Wl,--gc-sections","-o",binary]
    execute(cmd);return binary

def add(csvfile, category, algorithm, compiler, opt, iterations, mlen):
    binary=build(category,algorithm,compiler,opt)
    args=[binary,str(iterations)]+([str(mlen)] if category=="sign" else [])
    output=capture(args)
    rows=[];sizes=[]
    for line in output.splitlines():
        p=line.split(",")
        if p[0]=="sizes": sizes=[int(x) for x in p[1:]]
        elif len(p)==3: rows.append((p[0],int(p[1]),float(p[2])))
    sec=capture(["size",binary]).splitlines()[-1].split()
    text,data,bss=map(int,sec[:3])
    try: commit=capture(["git","-C",PQCLEAN,"rev-parse","--short","HEAD"])
    except: commit="unknown"
    header=["category","algorithm","implementation","compiler","optimization","operation",
            "iterations","time_ns","time_us","text_bytes","data_bytes","bss_bytes",
            "public_key_bytes","secret_key_bytes","output_bytes","message_or_shared_bytes",
            "pqclean_commit","cpu"]
    new=not csvfile.exists()
    with csvfile.open("a",newline="") as f:
        w=csv.writer(f)
        if new:w.writerow(header)
        for op,n,ns in rows:
            w.writerow([category,algorithm,"clean",compiler,opt,op,n,f"{ns:.3f}",f"{ns/1000:.3f}",
                        text,data,bss,*sizes,commit,platform.processor() or platform.machine()])
    print("[완료]",category,algorithm)

def main():
    p=argparse.ArgumentParser();s=p.add_subparsers(dest="cmd",required=True)
    s.add_parser("doctor");s.add_parser("list")
    r=s.add_parser("run");r.add_argument("--preset",choices=["easy","normal","full"],default="easy")
    r.add_argument("--compiler",choices=["gcc","clang"],default="gcc")
    r.add_argument("--opt",choices=["O0","O2","O3","Os","native","lto"],default="O3")
    o=s.add_parser("one");o.add_argument("--category",choices=["kem","sign"],required=True)
    o.add_argument("--algorithm",required=True);o.add_argument("--compiler",choices=["gcc","clang"],default="gcc")
    o.add_argument("--opt",choices=["O0","O2","O3","Os","native","lto"],default="O3")
    o.add_argument("--iterations",type=int,default=500);o.add_argument("--message-len",type=int,default=32)
    f=s.add_parser("flags");f.add_argument("--category",choices=["kem","sign"],required=True)
    f.add_argument("--algorithm",required=True);f.add_argument("--compiler",choices=["gcc","clang"],default="gcc")
    f.add_argument("--iterations",type=int,default=300)
    a=p.parse_args();BUILD.mkdir(exist_ok=True);RESULTS.mkdir(exist_ok=True)
    if a.cmd=="doctor":doctor();return
    if a.cmd=="list":
        for cat,base in [("kem","crypto_kem"),("sign","crypto_sign")]:
            print(f"[{cat}]")
            for x in sorted((PQCLEAN/base).iterdir()):
                if (x/"clean"/"api.h").exists():print(x.name)
        return
    if a.cmd=="one":
        out=RESULTS/"one_result.csv"
        if out.exists():out.unlink()
        add(out,a.category,a.algorithm,a.compiler,a.opt,a.iterations,a.message_len);return
    if a.cmd=="flags":
        out=RESULTS/"flags_results.csv"
        for opt in ["O0","O2","O3","Os","native","lto"]:
            try:add(out,a.category,a.algorithm,a.compiler,opt,a.iterations,32)
            except Exception as e:print("[건너뜀]",opt,e,file=sys.stderr)
        return
    out=RESULTS/"results.csv"
    if out.exists():out.unlink()
    ni={"easy":(500,100),"normal":(3000,500),"full":(10000,2000)}[a.preset]
    errors=[]
    for alg in KEMS:
        try:add(out,"kem",alg,a.compiler,a.opt,ni[0],32)
        except Exception as e:errors.append(f"kem/{alg}: {e}");print(errors[-1],file=sys.stderr)
    for alg in SIGNS:
        try:add(out,"sign",alg,a.compiler,a.opt,ni[1],32)
        except Exception as e:errors.append(f"sign/{alg}: {e}");print(errors[-1],file=sys.stderr)
    if errors:(RESULTS/"failures.txt").write_text("\n".join(errors))
    if not out.exists():raise SystemExit("모든 측정 실패: results/failures.txt 확인")

if __name__=="__main__":main()
