#!/usr/bin/env bash
# scripts/prepublish-check.sh — pre-publish validation for NetworkVet
# Run this script before publishing to npm to ensure everything is in order.
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== NetworkVet pre-publish check ==="
echo ""

# 1. Run all tests
echo "[1/4] Running tests..."
npm test
echo "      Tests passed."
echo ""

# 2. Build TypeScript
echo "[2/4] Building TypeScript..."
npm run build
echo "      Build succeeded."
echo ""

# 3. Verify dist/ contains expected entry points
echo "[3/4] Verifying dist/ contents..."
REQUIRED_FILES=(
  "dist/cli.js"
  "dist/rules/engine.js"
  "dist/parser/index.js"
  "dist/formatters/tty.js"
  "dist/formatters/json.js"
  "dist/formatters/sarif.js"
  "dist/formatters/matrix.js"
  "dist/formatters/rego.js"
  "dist/formatters/traffic.js"
  "dist/rego/generator.js"
  "dist/rego/index.js"
  "dist/webhook/server.js"
  "dist/webhook/index.js"
  "dist/traffic/parser.js"
  "dist/traffic/analyzer.js"
  "dist/reachability/evaluator.js"
  "dist/fixer/generator.js"
  "dist/diff/index.js"
)
MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "      MISSING: $f"
    MISSING=1
  fi
done
if [[ $MISSING -eq 1 ]]; then
  echo "      ERROR: one or more dist files are missing."
  exit 1
fi
echo "      All required dist files present."
echo ""

# 4. Dry-run pack to confirm package contents
echo "[4/4] Running npm pack --dry-run..."
npm pack --dry-run
echo ""

echo "=== All checks passed. Ready to publish. ==="
