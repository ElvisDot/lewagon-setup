#!/bin/bash

set -euo pipefail

LAST_DOC_UPDATE="$(grep '^LAST_DOC_UPDATE=' doc.sh | grep -o '[0-9]*')"
now="$(date '+%s')"
days="$(( (now - LAST_DOC_UPDATE) / 86400 ))"

echo "Doctor age is $days days"

if [ "$days" -gt "1" ]
then
	exit 1
fi

