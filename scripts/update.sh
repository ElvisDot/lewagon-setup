#!/bin/bash

set -euo pipefail

./scripts/check_wanted_versions.sh || exit 1

echo "[OK] all versions up to date. Updating doctors age..."

doc_code="$(cat doc.sh)"
# shellcheck disable=SC2001
echo "$doc_code" | sed "s/^LAST_DOC_UPDATE=.*/LAST_DOC_UPDATE=$(date '+%s')/" > doc.sh

