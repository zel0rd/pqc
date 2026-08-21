#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
rm -f results/flags_results.csv
python3 tools/lab.py flags --category kem --algorithm ml-kem-768 --iterations 300
python3 tools/lab.py flags --category sign --algorithm ml-dsa-65 --iterations 100
python3 tools/plot_results.py results/flags_results.csv results
echo "완료: results/flags_results.csv"
