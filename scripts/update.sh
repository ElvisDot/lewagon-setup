#!/bin/bash

set -euo pipefail

./scripts/check_wanted_versions.sh || exit 1

doc_gems="$(grep -o 'REQUIRED_GEMS = .*' doc.sh)"
lw_gems="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep 'REQUIRED_GEMS = ')"
if [ "$doc_gems" != "$lw_gems" ]
then
	echo "Error: wrong desired gems"
	echo ""
	echo "    doctor: $doc_gems"
	echo "  le wagon: $lw_gems"
	echo ""
	exit 1
fi

echo "[OK] all versions up to date. Updating doctors age..."

doc_code="$(cat doc.sh)"
# shellcheck disable=SC2001
echo "$doc_code" | sed "s/^LAST_DOC_UPDATE=.*/LAST_DOC_UPDATE=$(date '+%s')/" > doc.sh


