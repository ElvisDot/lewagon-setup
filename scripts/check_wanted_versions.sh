#!/bin/bash

set -euo pipefail

function check_match() {
	local name="$1"
	local wanted="$2"
	local latest="$3"
	if [ "$wanted" != "$latest" ]
	then
		echo "$name version missmatch:"
		echo "  wanted: $wanted"
		echo "  latest: $latest"
		exit 1
	fi
}

WANTED_POSTGRES_VERSION="$(grep '^WANTED_POSTGRES_VERSION=' doc.sh | cut -d"=" -f2)"
latest_postgres_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/macos.md | grep -oE 'brew install postgresql@[0-9]+' | cut -d@ -f2)"
check_match PostgreSQL "$WANTED_POSTGRES_VERSION" "$latest_postgres_version"

WANTED_NODE_VERSION="$(grep '^WANTED_NODE_VERSION=' doc.sh | cut -d"'" -f2)"
latest_node_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/windows.md | grep 'nvm install ' | awk '{ print $3 }')"
check_match node "$WANTED_NODE_VERSION" "$latest_node_version"

WANTED_RUBY_VERSION="$(grep '^WANTED_RUBY_VERSION=' doc.sh | cut -d"'" -f2)"
latest_ruby_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep "^REQUIRED_RUBY_VERSION" | cut -d'"' -f2)"
check_match Ruby "$WANTED_RUBY_VERSION" "$latest_ruby_version"

WANTED_DOTFILES_SHA="$(grep '^WANTED_DOTFILES_SHA=' doc.sh | cut -d"'" -f2)"
latest_dotfiles_sha="$(curl -s https://api.github.com/repos/lewagon/dotfiles/commits/master | jq -r .sha)"
check_match dotfiles "$WANTED_DOTFILES_SHA" "$latest_dotfiles_sha"

