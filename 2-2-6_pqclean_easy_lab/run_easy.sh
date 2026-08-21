#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ] || [ ! -d PQClean ]; then ./setup.sh; fi
source .venv/bin/activate
rm -f results/results.csv
python3 tools/lab.py run --preset easy --compiler gcc --opt O3
python3 tools/plot_results.py results/results.csv results
echo
echo "완료: results/results.csv, results/summary.md, results/*.png"
