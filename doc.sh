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
# _color_green="\e[0;32m"
# _color_yellow="\e[0;33m"
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
	printf '%b[%b-%b]%b %s\n' "$_color_WHITE" "$_color_RED" "$_color_WHITE" "$_color_red" "$1"
}

function warn() {
	printf '%b[%b!%b]%b %s\n' "$_color_WHITE" "$_color_YELLOW" "$_color_WHITE" "$_color_RESET" "$1"
}

function log() {
	printf '%b[*]%b %s\n' "$_color_WHITE" "$_color_RESET" "$1"
}

function okay() {
	printf '%b[%b+%b]%b %s\n' "$_color_WHITE" "$_color_GREEN" "$_color_WHITE" "$_color_RESET" "$1"
}

function check_internet() {
	if ping 8.8.8.8 -c1 -w1 &>/dev/null
	then
		return
	fi
	error "Error: could not ping 8.8.8.8 is your internet working?"
	exit 1
}

function check_dns() {
	local hosts
	# if it can ping either github.com or lewagon.com
	# dns is working
	hosts=(github.com lewagon.com)
	for host in "${hosts[@]}"
	do
		if ping "$host" -c1 -w1 &>/dev/null
		then
			return
		fi
	done
	error "Error: could not ping 8.8.8.8 is your internet working?"
	exit 1
}

function check_user() {
	if [[ "$UID" != "0" ]] && [[ "$EUID" != "0" ]]
	then
		return
	fi
	error "Error: do not run the script as root"
	exit 1
}

function check_basics() {
	check_colors
	check_internet
	check_dns
	check_user
}

function main() {
	check_basics
	log "Hi I am the doctor"
}

main

