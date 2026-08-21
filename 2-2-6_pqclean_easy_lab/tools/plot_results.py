#!/usr/bin/env python3
import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

csv_path=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(exist_ok=True)
df=pd.read_csv(csv_path)
for c in ["time_us","text_bytes"]:df[c]=pd.to_numeric(df[c])
for cat in sorted(df.category.unique()):
    x=df[df.category==cat]
    p=x.pivot_table(index="algorithm",columns="operation",values="time_us",aggfunc="mean")
    ax=p.plot(kind="bar",figsize=(10,5));ax.set_ylabel("Time per operation (microseconds)")
    ax.set_title(f"PQClean {cat.upper()} performance");plt.xticks(rotation=25,ha="right")
    plt.tight_layout();plt.savefig(out/f"{cat}_performance.png",dpi=180);plt.close()
    q=x.drop_duplicates(["algorithm","optimization"]).set_index("algorithm")
    ax=(q.text_bytes/1024).plot(kind="bar",figsize=(9,5));ax.set_ylabel("Linked .text size (KiB)")
    ax.set_title(f"PQClean {cat.upper()} linked code size");plt.xticks(rotation=25,ha="right")
    plt.tight_layout();plt.savefig(out/f"{cat}_code_size.png",dpi=180);plt.close()
chosen=df[df.operation.isin(["encaps","sign"])]
if len(chosen):
    fig,ax=plt.subplots(figsize=(9,6))
    for _,r in chosen.iterrows():
        ax.scatter(r.text_bytes/1024,r.time_us)
        ax.annotate(r.algorithm,(r.text_bytes/1024,r.time_us),xytext=(4,4),textcoords="offset points",fontsize=8)
    ax.set_xlabel("Linked .text size (KiB)");ax.set_ylabel("Encaps or Sign time (microseconds)")
    ax.set_title("Performance vs linked code size");plt.tight_layout()
    plt.savefig(out/"speed_vs_code_size.png",dpi=180);plt.close()
s=["# PQClean 실습 결과 요약",""]
for cat in sorted(df.category.unique()):
    s+=["## "+cat.upper()]
    x=df[df.category==cat]
    for op in sorted(x.operation.unique()):
        r=x[x.operation==op].sort_values("time_us").iloc[0]
        s.append(f"- 가장 빠른 `{op}`: **{r.algorithm}** ({r.time_us:.3f} μs/op)")
    r=x.drop_duplicates("algorithm").sort_values("text_bytes").iloc[0]
    s.append(f"- 가장 작은 링크 `.text`: **{r.algorithm}** ({r.text_bytes/1024:.2f} KiB)")
    s.append("")
(out/"summary.md").write_text("\n".join(s),encoding="utf-8")
print("\n".join(s))
