#!/usr/bin/env bash
# morgue end-to-end: forge synthetic logs -> scan -> verify artifacts + codes.
# Runs the real CLI as subprocesses, exactly like a user would.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"
fails=0

check() { # check <name> <condition exit code>
    if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails+1)); fi
}

echo "== morgue e2e =="

# 1. forge three families
for fam in lumma redline stealc; do
    $PY -m morgue forge --out "$WORK/logs" --family "$fam" --seed 42 --creds 50 --cookies 20 >/dev/null 2>&1
    check "forge $fam" $?
done

# 2. determinism: same seed twice -> identical bytes
$PY -m morgue forge --out "$WORK/d1" --family lumma --seed 7 >/dev/null 2>&1
$PY -m morgue forge --out "$WORK/d2" --family lumma --seed 7 >/dev/null 2>&1
diff -r "$WORK/d1/lumma" "$WORK/d2/lumma" >/dev/null 2>&1
check "forge determinism (byte-identical)" $?

# 3. multi-victim scan: 3 machines found, reports written
$PY -m morgue scan "$WORK/logs" --outdir "$WORK/out" --no-color --corp acme-corp.example > "$WORK/scan.txt" 2>&1
check "scan multi-victim (exit 0)" $?
grep -q "machines  : 3" "$WORK/scan.txt"
check "3 machines reported" $?
for f in report.json credentials.csv report.html; do
    [ -s "$WORK/out/$f" ]
    check "report artifact: $f" $?
done

# 4. reports are masked and path-clean
if grep -q "Password1!" "$WORK/out/report.json" || grep -q "Password1!" "$WORK/out/credentials.csv"; then
    check "masking enforced by default" 1
else
    check "masking enforced by default" 0
fi
if grep -qE "/home/|/Users/|C:\\\\" "$WORK/out/report.json" "$WORK/out/report.html"; then
    check "no host filesystem paths in reports" 1
else
    check "no host filesystem paths in reports" 0
fi

# 5. exit codes for automation
$PY -m morgue scan "$WORK/logs/lumma" --outdir "$WORK/out2" --quiet --fail-on medium >/dev/null 2>&1
[ $? -eq 10 ]; check "exit 10 at --fail-on medium" $?

# 6. ioc feed: 3 victim records, no secrets
$PY -m morgue ioc "$WORK/logs" --out "$WORK/iocs.jsonl" >/dev/null 2>&1
check "ioc feed written" $?
[ "$(wc -l < "$WORK/iocs.jsonl")" -eq 3 ]
check "3 ioc records" $?
grep -q "password" "$WORK/iocs.jsonl"; [ $? -ne 0 ]
check "ioc feed carries no secrets" $?

# 7. empty dir -> exit 3, missing path -> exit 2
mkdir -p "$WORK/empty"
$PY -m morgue scan "$WORK/empty" --outdir "$WORK/out3" >/dev/null 2>&1
[ $? -eq 3 ]; check "empty dir scan exits 3" $?
$PY -m morgue scan "$WORK/does-not-exist" >/dev/null 2>&1
[ $? -eq 2 ]; check "missing path scan exits 2" $?

# 8. zipapp runs standalone (if built)
if [ -f "dist/morgue.pyz" ]; then
    $PY dist/morgue.pyz forge --out "$WORK/pyz" --family stealc --seed 1 >/dev/null 2>&1
    check "morgue.pyz forge runs standalone" $?
    $PY dist/morgue.pyz scan "$WORK/pyz/stealc" --outdir "$WORK/pyz-out" --no-color >/dev/null 2>&1
    check "morgue.pyz scan runs standalone" $?
fi

echo "== $fails failure(s) =="
exit $((fails > 0))
