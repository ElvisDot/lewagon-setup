#!/bin/bash

set -euo pipefail

WANTED_RUBY_VERSION="$(grep '^WANTED_RUBY_VERSION=' doc.sh | cut -d"'" -f2)"
latest_ruby_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep "^REQUIRED_RUBY_VERSION" | cut -d'"' -f2)"

if [ "$WANTED_RUBY_VERSION" != "$latest_ruby_version" ]
then
	echo "Ruby version missmatch:"
	echo "  wanted: $WANTED_RUBY_VERSION"
	echo "  latest: $latest_ruby_version"
	exit 1
fi
