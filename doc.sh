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

arg_verbose=0
arg_full=0
arg_fix=0
arg_course=""

bootcamp=unkown

function show_help() {
	echo "usage: $(basename "$0") [OPTIONS]"
	echo "options:"
	echo "  --verbose|-v          Activate verbose output -vv for even more"
	echo "  --full                Takes longer and tests more"
	echo "  --fix                 The doctor by default does mostly diagnose. This does autofixing"
	echo "  --course <web|data>   Web and data camps have different setups"
}

function parse_args() {
	local flags
	local flag
	local arg
	while true
	do
		[[ "$#" -lt "1" ]] && break

		arg="$1"
		shift

		if [[ "${arg::2}" == "--" ]]
		then
			if [ "$arg" == "--help" ]
			then
				show_help
				exit 0
			elif [ "$arg" == "--full" ]
			then
				arg_full=1
			elif [ "$arg" == "--verbose" ]
			then
				arg_verbose=1
			elif [ "$arg" == "--fix" ]
			then
				arg_fix=1
			elif [ "$arg" == "--course" ]
			then
				arg_course="$1"
				bootcamp="$1"
				shift

				if [ "$bootcamp" != "web" ] && [ "$bootcamp" != "data" ]
				then
					echo "usage: $(basename "$0") --course <web|data>"
					exit 1
				fi
			else
				show_help
				exit 1
			fi
		elif [[ "${arg::1}" == "-" ]]
		then
			flags="${arg:1}"
			while IFS= read -n1 -r flag
			do
				if [[ "$flag" == "v" ]]
				then
					arg_verbose="$((arg_verbose+1))"
				elif [[ "$flag" == "h" ]]
				then
					show_help
					exit 0
				else
					echo "Error: unkown flag '$flag'"
					exit 1
				fi
			done < <(echo -n "$flags")
		else
			echo "Error: unkown argument '$arg'"
			exit 1
		fi
	done
}

parse_args "$@"

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
	warn "Warning: Could not establish SSL connection!"
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
	if [ "$arg_verbose" -gt "0" ]
	then
		warn "Warning: could not ping github.com"
	fi
	return 1
}

function detect_user() {
	if grep -qF ':1000:' /etc/passwd
	then
		grep ':1000:' /etc/passwd | cut -d':' -f1 | head -n1
	fi
	# This one showed all the users I created on my debian system
	# but not sure how much sense that makes
	# grep -Ev '(^root:|^postgres:|nologin$|false$|sync$)' /etc/passwd | cut -d':' -f1 | head -n1
}

function check_user() {
	if [[ "$UID" != "0" ]] && [[ "$EUID" != "0" ]]
	then
		return
	fi
	warn "Warning: do not run the script as root"
	local username
	local zsh_path
	zsh_path="$(command -v zsh)"
	if [ "$zsh_path" == "" ]
	then
		error "Error: you need zsh installed"
		exit 1
	fi

	username="$(detect_user)"
	if [ "$username" == "" ]
	then
		# grep NAME_REGEX /etc/adduser.conf
		while [[ ! "$username" =~ ^[a-z][-a-z0-9_]*$ ]]
		do
			log "Please pick a username that meets those conditions:"
			log " - not starting with a number"
			log " - only lowercase letters from a-z"
			log " - something short like your first name"
			read -r username
		done

		useradd "$username" --create-home --shell="$zsh_path" || {
			error "Error: failed to create user"
			exit 1;
		}
		log "Now pick a password for your linux user"
		log "Note you won't see what you are typing not even a *"
		passwd "$username"
	fi

	if ! id "$username" | grep -q sudo
	then
		groupadd sudo &>/dev/null
		usermod -aG sudo "$username"
	fi

	# todo: call powershell to set default user in wsl
	if is_windows
	then
		powershell.exe -c "ubuntu config --default-user $username"
	fi
}

function check_brew() {
	if [ -x "$(command -v brew)" ]
	then
		# brew found in path all good
		return
	fi
	if is_arm
	then
		if [ ! -f /opt/homebrew/bin/brew ]
		then
			/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
		fi

		# brew is installed but not in path
		if ! grep 'opt/homebrew' ~/.zprofile
		then
			# shellcheck disable=SC2016
			echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
			eval "$(/opt/homebrew/bin/brew shellenv)"
			warn "Warning: please restart your terminal for brew to work"
		fi
	else # x86
		if [ ! -f /usr/local/bin/brew ]
		then
			/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
		fi

		# x86 should not have path issues and even if
		# its not that common since all new macs are arm
	fi
}

detected_os=""
detected_distro=""
mac_version=""
mac_arch=""

function is_mac() {
	[[ "$detected_os" == "macOS" ]] && return 0
	return 1
}
function is_arm() {
	[[ "$mac_arch" =~ arm ]] && return 0
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
	elif grep -q Microsoft /proc/version || uname -a | grep -iq '^Linux.*Microsoft'
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
		mac_version="$detected_distro"
		mac_arch="$(arch)"
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
	log "Detected $_color_green$detected_os$_color_RESET $detected_distro $(is_arm && echo -e "$_color_green(arm)$_color_RESET")"
	if ! is_mac && ! is_ubuntu
	then
		warn "Warning: LeWagon setup recommends Ubuntu"
		warn "         other distros are fine if you know what you are doing"
	elif is_mac
	then
		local mac_major
		mac_major="${mac_version%%.*}"
		if [ "$mac_major" -lt "11" ]
		then
			warn "Warning: your macOS is outdated please do a update"
		fi
	fi
}

function check_basics() {
	if ! check_dns
	then
		check_internet
	fi
	if [ "$arg_full" == "1" ]
	then
		check_ssl
	fi
	check_shell
	if is_windows || is_linux
	then
		check_user
	fi
}

function check_shell() {
	if [[ "$SHELL" =~ zsh ]]
	then
		return
	fi

	if [ "$arg_fix" == "0" ]
	then
		warn "Warning: zsh is not your default shell"
	else
		if [ -x "$(command -v zsh)" ]
		then
			chsh -s "$(command -v zsh)"
		else
			error "Error: did not find zsh"
			if is_ubuntu
			then
				echo "$_color_WHITE"
				echo "  sudo apt install zsh"
				echo "$_color_RESET"
			elif is_mac
			then
				echo "$_color_WHITE"
				echo "  brew install zsh"
				echo "$_color_RESET"
			fi
			exit 1
		fi
	fi
}

function check_vscode() {
	if [ -x "$(command -v code)" ]
	then
		return
	fi
	local vs_path="/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
	if [ -f "$vs_path"/code ]
	then
		# The proper way would be to do what brew does
		# I assume they sym link the binary to something that is in the PATH
		# Or better let brew do it by reinstalling vscode
		# The issue tho is that deleting vscode might cause data loss?
		# Like user settings or something like that not sure what is stored
		# in the app dir on mac
		#
		# So lets go with this hacky but safe method for now
		# Which also sadly requires restarting the shell
		if grep -q "$vs_path" ~/.zshrc
		then
			echo "export PATH=\"\$PATH:$vs_path\"" >> ~/.zshrc
		fi
		return
	fi
	local dl_path="/Users/$USER/Downloads/Visual Studio Code.app"
	if [ -d "$dl_path" ]
	then
		# todo: test this and then do it automatically when --fix is active
		warn "Warning: vscode is found in the ~/Downloads folder"
		warn "         It should be in your Applications folder to fix it run:"
		warn ""
		warn "$_color_WHITE  mv ~/Downloads/Visual\ Studio\ Code.app /Applications  $_color_RESET"
		warn ""
	fi
}

function is_data() {
	[[ "$bootcamp" == "data" ]] && return 0
	return 1
}
function is_web() {
	[[ "$bootcamp" == "web" ]] && return 0
	return 1
}

function detect_bootcamp() {
	if [ "$arg_course" != "" ]
	then
		return
	fi
	# assume web by default
	# detect data based on heuristics
	bootcamp=web
	if [ -x "$(command -v ncdu)" ]
	then
		bootcamp=data
	fi
	log "Assuming $_color_YELLOW$bootcamp$_color_RESET bootcamp"
}

function install_rbenv() {
	if [ -x "$(command -v rbenv)" ]
	then
		return
	fi

	# todo: do this better
	if is_mac && is_arm
	then
		if [ -f /opt/homebrew/bin/rbenv ]
		then
			error "Error: Failed to fix rbenv. Try restarting your terminal"
			error "       if that does not help please report the issue here"
			error ""
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			error ""
			exit 1
		fi
	fi
	if is_linux || is_windows
	then
		if [ -f ~/.rbenv/bin/rbenv ]
		then
			error "Error: Failed to fix rbenv. Try restarting your terminal"
			error "       if that does not help please report the issue here"
			error ""
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			error ""
			exit 1
		fi
	fi

	rvm implode &>/dev/null && sudo rm -rf ~/.rvm

	if is_linux || is_windows
	then
		if is_ubuntu && [ ! -x "$(command -v g++)" ]
		then
			sudo apt-get update -y
			sudo apt-get install -y \
				build-essential \
				tklib zlib1g-dev \
				libssl-dev libffi-dev \
				libxml2 libxml2-dev \
				libxslt1-dev libreadline-dev
		fi
		git clone https://github.com/rbenv/rbenv.git ~/.rbenv
		git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
		warn "Warning: Please restart your terminal and try again"
		exit 1
	elif is_mac
	then
		brew install rbenv
		warn "Warning: Please restart your terminal and try again"
		exit 1
	fi
	error "Error: Failed to get rbenv. Try restarting your terminal"
	error "       if that does not help please report the issue here"
	error ""
	error "       https://github.com/ElvisDot/lewagon-setup/issues"
	exit 1
}

function check_ruby() {
	if [ ! -x "$(command -v rbenv)" ]
	then
		install_rbenv
	fi
	# todo: check ruby version
}

function check_dotfiles() {
	local dotfiles=(
		~/.aliases
		~/.gitconfig
		~/.irbrc
		~/.rspec
		~/.zprofile
		~/.zshrc
	)
	local dotfile
	local broken_links=0
	for dotfile in "${dotfiles[@]}"
	do
		# ignore non symlink dotfiles
		[[ -L "$dotfile" ]] || break

		# if the symlink is dead
		# (pointing to a invalid file)
		# delete it so the lewagon setup can relink it
		if [ ! -e "$dotfile" ]
		then
			rm "$dotfile"
			broken_links=1
		fi
	done
	if [ "$broken_links" == "1" ]
	then
		# todo: fix this automatically
		error "Error: you had broken symlinks"
		error "         please run the dotfiles install again"
		exit 1
	fi
}

function main() {
	check_colors
	device_info
	check_basics
	if is_mac
	then
		check_brew
	fi
	detect_bootcamp
	check_vscode
	check_dotfiles
	if is_web
	then
		check_ruby
	fi
	log "Hi I am the doctor"
}

main

