#!/usr/bin/env bash
# build dist/morgue.pyz - single-file zipapp, stdlib only, runs anywhere with python3
set -eu
cd "$(dirname "$0")/.."
rm -rf build_pyz dist
mkdir -p dist build_pyz
cp -r morgue build_pyz/morgue
python3 -m zipapp build_pyz -p "/usr/bin/env python3" -m "morgue.cli:main" -o dist/morgue.pyz
rm -rf build_pyz
ls -la dist/morgue.pyz
python3 dist/morgue.pyz --version
