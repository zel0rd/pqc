#!/usr/bin/env bash

set -euo pipefail

# 기준 인증서 크기
base_file="ecdsa_p256.crt"

if [[ ! -f "$base_file" ]]; then
    echo "오류: 기준 파일 '$base_file'이 없습니다."
    exit 1
fi

base=$(stat -c%s "$base_file")

printf "%-25s %12s %10s %10s  %s\n" \
    "Certificate" "Bytes" "KB" "Ratio" "Chart"
printf '%*s\n' 90 '' | tr ' ' '-'

for f in *.crt; do
    [[ -e "$f" ]] || continue

    size=$(stat -c%s "$f")

    kb=$(awk -v size="$size" \
        'BEGIN { printf "%.2f", size / 1024 }')

    ratio=$(awk -v size="$size" -v base="$base" \
        'BEGIN { printf "%.2f", size / base }')

    bar=$(awk -v size="$size" \
        'BEGIN {
            n = int(size / 200)
            if (n < 1) n = 1
            for (i = 0; i < n; i++) {
                printf "█"
            }
        }')

    printf "%-25s %12d %10s %9sx  %s\n" \
        "$f" "$size" "$kb" "$ratio" "$bar"
done
