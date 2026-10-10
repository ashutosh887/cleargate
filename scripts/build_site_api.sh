#!/usr/bin/env bash
# Vendor the stub bank into the site's serverless function, then deploy:
#   scripts/build_site_api.sh && vercel deploy site --prod --yes
set -euo pipefail
cd "$(dirname "$0")/.."
lib=site/api/_lib
rm -rf "$lib"
mkdir -p "$lib/fixtures"
rsync -a --exclude '__pycache__' --exclude 'web/static' --exclude '*.md' cleargate "$lib/"
cp policy.yaml verify.py "$lib/"
cp fixtures/seed_bank.sql "$lib/fixtures/"
echo "vendored into $lib ($(du -sh "$lib" | cut -f1))"
