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

WANTED_PYTHON_VERSION="$(grep '^WANTED_PYTHON_VERSION=' doc.sh | cut -d"'" -f2)"
latest_python_version="$(curl -s https://raw.githubusercontent.com/lewagon/data-setup/master/macOS.md | grep -E "^pyenv install [^ ]+" | cut -d' ' -f3 | tail -n 1)"
check_match Python "$WANTED_PYTHON_VERSION" "$latest_python_version"

WANTED_DOTFILES_SHA="$(grep '^WANTED_DOTFILES_SHA=' doc.sh | cut -d"'" -f2)"
latest_dotfiles_sha="$(curl -s https://api.github.com/repos/lewagon/dotfiles/commits/master | jq -r .sha)"
check_match dotfiles "$WANTED_DOTFILES_SHA" "$latest_dotfiles_sha"

WANTED_GEMS="$(grep -o 'REQUIRED_GEMS = .*' doc.sh)"
latest_gems="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep 'REQUIRED_GEMS = ')"
check_match gems "$WANTED_GEMS" "$latest_gems"

WANTED_EXT_WEB="$(grep '^WANTED_VSCODE_EXTENSIONS_WEB=' doc.sh | cut -d'"' -f2)"
latest_ext_web="$(curl -s 'https://raw.githubusercontent.com/lewagon/setup/master/macos.md' | grep '^code --install-extension ' | cut -d' ' -f3 | sed ':a;N;$!ba;s/\n/\\n/g')"
check_match 'vscode extensions (web)' "$WANTED_EXT_WEB" "$latest_ext_web"

function check_readme() {
	local ip
	local found=0
	while read -r ip
	do
		if grep 'raw.githubusercontent.com.*/etc/hosts' README.md | grep -qF "$ip"
		then
			found=1
			break
		fi
	done < <(host raw.githubusercontent.com | grep -o 'address.*' | cut -d' ' -f2)

	if [ "$found" == "0" ]
	then
		echo "Error: README.md does not contain correct ip"
		grep 'raw.githubusercontent.com.*/etc/hosts' README.md
		echo "Correct ips:"
		host raw.githubusercontent.com
		exit 1
	fi
}

check_readme
