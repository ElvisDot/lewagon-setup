#!/bin/bash

_color_RESET="\e[0m"
# _color_BLACK="\e[1;30m"
_color_RED="\e[1;31m"
_color_GREEN="\e[1;32m"
_color_YELLOW="\e[1;33m"
# _color_BLUE="\e[1;34m"
# _color_MAGENTA="\e[1;35m"
# _color_CYAN="\e[1;36m"
_color_WHITE="\e[1;37m"

# _color_BOLD="\033[1m"

# _color_black="\e[0;30m"
_color_red="\e[0;31m"
_color_green="\e[0;32m"
_color_yellow="\e[0;33m"
# _color_blue="\e[0;34m"
# _color_magenta="\e[0;35m"
# _color_cyan="\e[0;36m"
# _color_white="\e[0;37m"

function check_colors() {
	if [ "$NO_COLOR" == "" ] && [ -t 1 ] && [[ "$TERM" =~ color ]]
	then
		return
	fi
	local color
	# shellcheck disable=SC2154
	for color in "${!_color_@}"
	do
		eval "$color=''"
	done
}

function error() {
	printf '%b[%b-%b]%b %s%b\n' "$_color_WHITE" "$_color_RED" "$_color_WHITE" "$_color_red" "$1" "$_color_RESET"
}

function warn() {
	printf '%b[%b!%b]%b %s%b\n' "$_color_WHITE" "$_color_YELLOW" "$_color_WHITE" "$_color_yellow" "$1" "$_color_RESET"
}

function log() {
	printf '%b[*]%b %b\n' "$_color_WHITE" "$_color_RESET" "$1"
}

function okay() {
	printf '%b[%b+%b]%b %s\n' "$_color_WHITE" "$_color_GREEN" "$_color_WHITE" "$_color_RESET" "$1"
}

function check_ssl() {
	local host
	local hosts=(https://github.com https://lewagon.com https://google.com)
	for host in "${hosts[@]}"
	do
		if [ -x "$(command -v curl)" ]
		then
			curl "$host" &>/dev/null && return
		elif [ -x "$(command -v wget)" ]
		then
			wget "$host" &>/dev/null && return
		fi
	done
	warning "Warning: Could not establish SSL connection!"
}

function check_internet() {
	local ip
	# Even the stable LeWagon munich office had a hiccup for 8.8.8.8
	# So give it some attempts
	local ips=(8.8.8.8 8.8.4.4 1.1.1.1)
	for ip in "${ips[@]}"
	do
		if ping "$ip" -c 1 -W 2 &>/dev/null
		then
			return
		fi
	done

	# Some networks including github CI might block ping
	# So do a http fallback test before concluding the internet is down
	local host
	local hosts=(http://github.com http://lewagon.com http://google.com)
	for host in "${hosts[@]}"
	do
		if [ -x "$(command -v curl)" ]
		then
			curl "$host" &>/dev/null && return
		elif [ -x "$(command -v wget)" ]
		then
			wget "$host" &>/dev/null && return
		fi
	done
	error "Error: could not ping 8.8.8.8 is your internet working?"
	exit 1
}

function check_dns() {
	local host
	# if it can ping either github.com or lewagon.com
	# dns is working
	local hosts=(github.com lewagon.com)
	for host in "${hosts[@]}"
	do
		if ping "$host" -c1 -w1 &>/dev/null
		then
			return 0
		fi
	done
	error "Error: could not ping github.com"
	return 1
}

function check_user() {
	if [[ "$UID" != "0" ]] && [[ "$EUID" != "0" ]]
	then
		return
	fi
	error "Error: do not run the script as root"
	exit 1
}

function check_brew() {
	if [ -x "$(command -v brew)" ]
	then
		# brew found in path all good
		return
	fi
	# todo: check architecture
	if [ -f /opt/homebrew/bin/brew ]
	then
		# brew is installed but not in path
		if ! grep 'opt/homebrew' ~/.zprofile
		then
			# shellcheck disable=SC2016
			echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
			exec zsh
		fi
	fi
}

detected_os=""
detected_distro=""

function is_mac() {
	[[ "$detected_os" == "macOS" ]] && return 0
	return 1
}
function is_linux() {
	[[ "$detected_os" == "Linux" ]] && return 0
	return 1
}
function is_ubuntu() {
	[[ "$detected_distro" =~ [Uu]buntu ]] && return 0
	return 1
}
function is_windows() {
	[[ "$detected_os" == "WSL" ]] && return 0
	return 1
}

function device_info() {
	# os
	if [[ $OSTYPE == 'darwin'* ]]
	then
		detected_os='macOS'
	elif grep -q Microsoft /proc/version
	then
		detected_os='WSL'
	elif [[ "$(uname)" == "Linux" ]]
	then
		detected_os='Linux'
	else
		error "Error: failed to detect your operating system"
		error "       please report this here https://github.com/ElvisDot/lewagon-setup/issues"
		exit 1
	fi

	# distro/version
	if is_mac
	then
		detected_distro="$(sw_vers -productVersion)"
	elif is_linux || is_windows
	then
		if [ -n "$(command -v lsb_release)" ]
		then
			detected_distro=$(lsb_release -s -d)
		elif [ -f "/etc/os-release" ]
		then
			detected_distro=$(grep PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '="')
		elif [ -f "/etc/debian_version" ]
		then
			detected_distro="Debian $(cat /etc/debian_version)"
		elif [ -f "/etc/redhat-release" ]
		then
			detected_distro=$(cat /etc/redhat-release)
		else
			detected_distro="$(uname -s) $(uname -r)"
		fi
	else
		error "Something went wrong"
		exit 1
	fi
	log "Detected $_color_green$detected_os$_color_RESET $detected_distro"
	if is_linux && ! is_ubuntu
	then
		warn "Warning: LeWagon setup recommends Ubuntu"
		warn "         other distros are fine if you know what you are doing"
	fi
}

function check_basics() {
	check_colors
	if ! check_dns
	then
		check_internet
	fi
	check_ssl
	check_user
}

function main() {
	device_info
	check_basics
	if is_mac
	then
		check_brew
	fi
	log "Hi I am the doctor"
}

main

