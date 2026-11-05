#!/usr/bin/env bash
# End-to-end CLI test using only offline capabilities (no network):
# numbering-plan investigation, hash inventory, authorization gating,
# export, and deletion against a throwaway database.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DB="$WORK/test.sqlite"

(cd "$ROOT/rust" && cargo build -q -p spectre-cli)
SPECTRE="$ROOT/rust/target/debug/spectre"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "- phone investigation (offline provider)"
OUTPUT="$("$SPECTRE" --db "$DB" investigate phone "+44 20 7946 0958" --providers phone-numbering --purpose "CI offline integration test")"
grep -q "Finished: Completed" <<<"$OUTPUT" || fail "investigation did not complete: $OUTPUT"
ID="$("$SPECTRE" --db "$DB" --json list | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["id"])')"

echo "- exports"
"$SPECTRE" --db "$DB" export "$ID" --format csv | grep -q "phone_metadata" || fail "CSV export missing finding"
"$SPECTRE" --db "$DB" export "$ID" --format json | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["format"]=="spectre.investigation"' || fail "JSON export invalid"

echo "- authorization record is required"
if "$SPECTRE" --db "$DB" investigate phone "+16502530000" --providers phone-numbering --purpose "x" 2>/dev/null; then
  fail "investigation without an authorization record was accepted"
fi

echo "- breach lookups require verified ownership"
if "$SPECTRE" --db "$DB" call breach.lookup '{"email":"someone@example.org"}' 2>"$WORK/err"; then
  fail "unverified breach lookup was accepted"
fi
grep -q "AuthorizationRequired" "$WORK/err" || fail "expected AuthorizationRequired"

echo "- hash inventory"
printf 'alice:$2b$12$KIXQJm0p0yQxQ1Lw7VbKQe2z0Yp0u5vD9n9H1l3uQ1mJ1qJ1qJ1qG\nbob:5f4dcc3b5aa765d61d8327deb882cf99\n' > "$WORK/hashes.txt"
"$SPECTRE" --db "$DB" hash-inventory "$WORK/hashes.txt" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["hashes_analyzed"]==2 and d["overall"]=="critical", d' || fail "hash inventory"

echo "- deletion"
"$SPECTRE" --db "$DB" call investigation.delete "{\"id\":\"$ID\"}" >/dev/null
"$SPECTRE" --db "$DB" --json list | python3 -c 'import sys,json; assert json.load(sys.stdin)==[]' || fail "investigation not deleted"

echo "CLI offline integration test passed"
