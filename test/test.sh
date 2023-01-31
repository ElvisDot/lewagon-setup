#!/bin/bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P )"
cd "$SCRIPTPATH" || exit 1
cd .. || exit 1

if [ ! -d test/ ]
then
	echo "Error: test/ not found"
	exit 1
fi
if [ ! -f doc.sh ]
then
	echo "Error: doc.sh not found"
	exit 1
fi

# docker build -t doc -f test/Dockerfile .
# docker rm doc
# docker run --name doc -t doc

read -r -d '' expected_logs <<'EOF'
[!] Warning: no ~/.ssh/config found
[-] Error: no LeWagon ssh key found
[-]        try running this command
[-]
[-]        gh auth login
[-]
EOF

expected_len="$(echo "$expected_logs" | wc -l)"
if [ "$(docker logs doc | tail -n "$expected_len")" != "$expected_logs" ]
then
	echo "Error: log does not match expectation"
	echo "expected logs"
	echo "$expected_logs"
	echo "got logs:"
	docker logs doc | tail -n "$expected_len"
	diff -u --color=always <(docker logs doc | tail -n "$expected_len") <(echo "$expected_logs")
fi

