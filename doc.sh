#!/usr/bin/env bash

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
arg_unix_name=""

bootcamp=unkown

num_warnings=0
num_errors=0

MIN_DISK_SPACE_GB=10

WANTED_RAILS_MAJOR_VERSION=7
WANTED_WSL_VERSION=2
WANTED_POSTGRES_VERSION=15
WANTED_NODE_VERSION='v16.15.1'
WANTED_RUBY_VERSION='3.1.2'

if [ "${BASH_VERSINFO:-0}" -lt 3 ]
then
	echo "Error: your bash version $BASH_VERSION is too old"
	exit 1
fi

UNAME_MACHINE="unkown"
HOMEBREW_PREFIX="/usr/local"
if [ -f /usr/bin/uname ]
then
	UNAME_MACHINE="unkown"
else
	# straight copy from the homebrew install script
	# https://github.com/Homebrew/install/blob/95648ef45c8d59a44fa4ab8f29cdcf17d6ec48ac/install.sh#L127-L138
	UNAME_MACHINE="$(/usr/bin/uname -m)"
	if [[ "${UNAME_MACHINE}" == "arm64" ]]
	then
		# On ARM macOS, this script installs to /opt/homebrew only
		HOMEBREW_PREFIX="/opt/homebrew"
		# HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}"
	else
		# On Intel macOS, this script installs to /usr/local only
		HOMEBREW_PREFIX="/usr/local"
		# HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}/Homebrew"
	fi
fi

# Auto say yes on new ssh connections when being prompted this
# Are you sure you want to continue connecting (yes/no/[fingerprint])
export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no"

function show_help() {
	echo "usage: $(basename "$0") [OPTIONS]"
	echo "options:"
	echo "  --verbose|-v          Activate verbose output -vv for even more"
	echo "  --full                Takes longer and tests more"
	echo "  --fix                 The doctor by default does mostly diagnose. This does autofixing"
	echo "  --course <web|data>   Web and data camps have different setups"
	echo "  --unix-name <name>    Pick your mac/linux username"
}

function wanted_node_version() {
	echo "$WANTED_NODE_VERSION"
}

function wanted_ruby_version() {
	# We could get the latest version from here
	#
	# curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep "^REQUIRED_RUBY_VERSION" | cut -d'"' -f2
	#
	# but doing http requests is slow
	# so maybe add this to the CI
	# or only if some last_updated variable
	# is more than x days ago
	echo "$WANTED_RUBY_VERSION"
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
			elif [ "$arg" == "--unix-name" ]
			then
				arg_unix_name="$1"
				shift

				if [ "$arg_unix_name" == "" ]
				then
					echo "usage: $(basename "$0") --unix-name <name>"
					exit 1
				fi
				# grep NAME_REGEX /etc/adduser.conf
				if [[ ! "$arg_unix_name" =~ ^[a-z][-a-z0-9_]*$ ]]
				then
					echo "Please pick a username that meets those conditions:"
					echo " - not starting with a number"
					echo " - only lowercase letters from a-z"
					echo " - something short like your first name"
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
	local msg="$1"
	# only the first print of every
	# error section gets counted
	# a multi line error is not multiple errors
	if [[ "$msg" =~ Error: ]]
	then
		num_errors="$((num_errors + 1))"
	fi
	printf '%b[%b-%b]%b %b%b\n' "$_color_WHITE" "$_color_RED" "$_color_WHITE" "$_color_red" "$msg" "$_color_RESET"
}

function warn() {
	local msg="$1"
	local nl='\n'
	if [ "$msg" == "-n" ]
	then
		nl=''
		shift
		msg="$1"
	fi
	if [[ "$msg" =~ Warning: ]]
	then
		num_warnings="$((num_warnings + 1))"
	fi
	printf '%b[%b!%b]%b %b%b%b' "$_color_WHITE" "$_color_YELLOW" "$_color_WHITE" "$_color_yellow" "$msg" "$_color_RESET" "$nl"
}

function log() {
	printf '%b[*]%b %b\n' "$_color_WHITE" "$_color_RESET" "$1"
}

function okay() {
	printf '%b[%b+%b]%b %b\n' "$_color_WHITE" "$_color_GREEN" "$_color_WHITE" "$_color_RESET" "$1"
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

function fail_if_no_internet() {
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

function password_note() {
	# todo: instead of prining some messages on howto change the password
	#       just run the passwd command and input the old password already
	#       so the user is forced to pick a password on shell launch
	#       if that returns a 0 exit code
	#       remove the code from the zshrc
	#
	#       or would that be adding too much complexity?
	#       creating a even more buggy and confusing setup?
	echo 'echo "your password is 123"'
	echo 'echo "to change it run this command:"'
	echo 'echo ""'
	echo 'echo "  passwd"'
	echo 'echo ""'
}

function check_user_windows() {
	is_windows || return
	if [[ "$UID" != "0" ]] && [[ "$EUID" != "0" ]]
	then
		return
	fi

	if [ "$arg_fix" == "1" ]
	then
		warn "Warning: do not run the script as root"
	else
		error "Error: do not run the script as root"
		error "       if you only have a root user and want to fix your setup"
		error "       run the doctor with the $_color_WHITE --fix $_color_red flag"
		exit 1
	fi

	local username
	local zsh_path
	zsh_path="$(command -v zsh)"
	if [ "$zsh_path" == "" ]
	then
		sudo apt-get install -y zsh
	fi
	if [ "$zsh_path" == "" ]
	then
		error "Error: you need zsh installed"
		exit 1
	fi

	username="$(detect_user)"
	if [ "$username" == "" ]
	then
		if [ "$arg_unix_name" == "" ]
		then
			error "Error: you are missing a user please pick a name"
			error "       and call the doctor with this argument:"
			error ""
			error "       ${_color_WHITE}--unix-name ${_color_YELLOW}a_name_you_pick"
			error ""
			exit 1
		fi

		username="$arg_unix_name"

		useradd "$username" --create-home --shell="$zsh_path" || {
			error "Error: failed to create user";
			exit 1;
		}


		# deprecated interactive stuff

		# log "Now pick a password for your linux user"
		# log "Note you won't see what you are typing not even a *"
		# passwd "$username"

		printf "123\n123\n" | passwd "$username"
		password_note >> /home/"$username"/.zshrc
	fi

	if ! id "$username" | grep -q sudo
	then
		groupadd sudo &>/dev/null
		usermod -aG sudo "$username"
	fi
	if ! id "$username" | grep -q docker && is_data
	then
		groupadd docker &>/dev/null
		usermod -aG docker "$username"
	fi

	powershell.exe -c "ubuntu config --default-user $username"
	warn "Warning: please restart your terminal"
	exit 1
}

function check_brew() {
	if [ -x "$(command -v brew)" ]
	then
		# brew found in path all good
		return
	fi

	if [ ! -f ${HOMEBREW_PREFIX}/bin/brew ]
	then
		# install brew
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

		# failed install
		if [ ! -f ${HOMEBREW_PREFIX}/bin/brew ]
		then
			error "Error: Unexpected brew install. Try restarting your terminal"
			error "       if that does not help please report the issue here"
			error ""
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			error ""
			exit 1
		fi
	fi

	persist_brew_in_path

	if [ -x "$(command -v brew)" ]
	then
		# monkey patch brew into PATH for the runtime of the doctor
		# to avoid user interaction (terminal restart/exec zsh/source rc file)
		eval "$(${HOMEBREW_PREFIX}/bin/brew shellenv)"
		if [ -x "$(command -v brew)" ]
		then
			# there is no need to diagnose or install anything if
			# brew is not installed
			error "Error: Failed to install brew. Try restarting your terminal"
			error "       if that does not help please report the issue here"
			error ""
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			error ""
			exit 1
		fi
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
	local arm_note=''
	arm_note="$(is_arm && echo -e " $_color_green(arm)$_color_RESET")"
	local wsl_version=''
	local wsl_note=''
	if is_windows && [ -x "$(command -v wsl.exe)" ]
	then
		# wsl.exe -l -v output looks like this
		#   NAME                   STATE           VERSION
		# * Ubuntu                 Running         2
		#   docker-desktop-data    Stopped         2
		#   docker-desktop         Stopped         2
		#
		# But the output is not very clean thats why it needs
		# the iconv step
		# see https://askubuntu.com/a/1394244
		local wsl_lv
		wsl_lv="$(wsl.exe -l -v | iconv -f utf16 | tr -d '\r')"
		wsl_default_version="$(echo "$wsl_lv" | grep '[[:space:]]*\*' | awk '{ print $4 }' | tail -n1)"
		is_running_default="$(echo "$wsl_lv" | grep '[[:space:]]*\*' | grep "[[:space:]]${WSL_DISTRO_NAME}[[:space:]]")"
		if [ "$is_running_default" != "" ]
		then
			wsl_version="$(echo "$wsl_lv" | grep "[[:space:]]${WSL_DISTRO_NAME}[[:space:]]" | awk '{ print $4 }' | tail -n1)"
		else
			# the leading * makes the version the 4th column in awk
			# if its not the default its the 3rd column
			wsl_version="$(echo "$wsl_lv" | grep "[[:space:]]${WSL_DISTRO_NAME}[[:space:]]" | awk '{ print $3 }' | tail -n1)"
		fi
		wsl_note="$_color_yellow WSL $wsl_version$_color_RESET"
	fi
	log "Detected $_color_green$detected_os$_color_RESET $detected_distro$arm_note$wsl_note"
	if ! is_mac && ! is_ubuntu
	then
		warn "Warning: Le Wagon setup recommends Ubuntu"
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
	if is_windows
	then
		local winver
		winver="$(powershell.exe -c "[System.Environment]::OSVersion.Version.Major" | tr -d '\r')"
		# note that winver is 10 on windows 11 but it is less than 10 on windows 8
		if [ "$winver" -lt "10" ]
		then
			warn "Warning: your windows is outdated please do a update"
		fi
		# intentionally check for 1 instead of
		# less than 2 or unequal 2
		# because a new fancy better wsl might release that
		# does not have a numeric version
		if [ "$wsl_version" != "$WANTED_WSL_VERSION" ]
		then
			error "Error: you are running ${_color_RED}WSL $wsl_version$_color_red"
			error "       please get ${_color_GREEN}WSL $WANTED_WSL_VERSION$_color_red instead."
			error ""
			error "       https://github.com/lewagon/setup/blob/master/windows.md#upgrade-to-wsl-2"
			error ""
		elif [ "$wsl_default_version" != "$WANTED_WSL_VERSION" ]
		then
			error "Error: your default WSL version is $_color_RED$_color_red instead of $_color_YELLOW$WANTED_WSL_VERSION"
		fi
		if [ "$is_running_default" == "" ]
		then
			warn "Warning: your current WSL is not set as default"
		fi
	fi

	# bash version
	local bash_version="$BASH_VERSION"
	if [ "${BASH_VERSINFO:-0}" -gt 3 ]
	then
		bash_version="$_color_green$bash_version"
	else
		bash_version="$_color_red$bash_version"
	fi
	log "Running ${_color_WHITE}bash$_color_RESET version $bash_version"
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

function fix_dns_wsl() {
	if [ "$arg_fix" == "1" ]
	then
		if [ -f /etc/resolv.conf ]
		then
			if ! mkdir -p /tmp/lewagon-doc
			then
				error "Error: failed to create backup folder /tmp/lewagon-doc"
				exit 1
			fi
			local backup_conf
			if ! backup_conf="$(mktemp /tmp/lewagon-doc/XXXXXX_resolv.conf.backup)"
			then
				error "Error: failed to create temp backup file"
				exit 1
			fi
			cat /etc/resolv.conf > "$backup_conf"
			sudo rm /etc/resolv.conf
			log "Updating $_color_WHITE/etc/resolv.conf$_color_RESET to fix dns."
			log "The old resolv.conf is backed up at $_color_green$backup_conf$_color_RESET"
		fi
		sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
		sudo bash -c 'echo "[network]" > /etc/wsl.conf'
		sudo bash -c 'echo "generateResolvConf = false" >> /etc/wsl.conf'
		sudo chattr +i /etc/resolv.conf
		return
	fi
	error "Error: your dns is not working. Try running these commands"
	error ""
	error "      ${_color_WHITE}sudo rm /etc/resolv.conf"
	error "      ${_color_WHITE}sudo bash -c 'echo \"nameserver 8.8.8.8\" > /etc/resolv.conf'"
	error "      ${_color_WHITE}sudo bash -c 'echo \"[network]\" > /etc/wsl.conf'"
	error "      ${_color_WHITE}sudo bash -c 'echo \"generateResolvConf = false\" >> /etc/wsl.conf'"
	error "      ${_color_WHITE}sudo chattr +i /etc/resolv.conf"
	error ""
	error "      or run the doctor with $_color_WHITE--fix"
}

function check_basics() {
	if ! check_dns
	then
		fail_if_no_internet

		if is_windows
		then
			fix_dns_wsl
		fi
	fi
	if [ "$arg_full" == "1" ]
	then
		check_ssl
	fi
	check_shell
	if is_windows || is_linux
	then
		check_user_windows
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
	if [ -x "$(command -v ncdu)" ] || [ -x "$(command -v direnv)" ]
	then
		bootcamp=data
	fi
	if [ -x "$(command -v code)" ]
	then
		if code --list-extensions | grep -q ruby
		then
			bootcamp=web
		fi
		if code --list-extensions | grep -Eqi '(jupyter|pylance)'
		then
			bootcamp=data
		fi
	fi
	if [ -d ~/.pyenv ]
	then
		bootcamp=data
	elif [ -d ~/.rbenv ]
	then
		bootcamp=web
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

	if [ -d ~/.rvm ] || [ -x "$(command -v rvm)" ]
	then
		if [ "$arg_fix" == "1" ]
		then
			rvm implode &>/dev/null
			if [ -d ~/.rvm ]
			then
				sudo rm -rf ~/.rvm
			fi
		else
			# this is not redundant with the
			# check_rvm function because
			# it only runs if we install a missing rbenv
			# this will not be printed if both rbenv and rvm
			# are installed
			warn "Warning: found rvm! You might want to uninstall that"
			warn ""
			warn "         ${_color_WHITE}rvm implode"
			warn "         ${_color_WHITE}rm -rf ~/.rvm"
			warn ""
			warn "         or run the doctor with $_color_WHITE--fix"
		fi
	fi

	if [ "$arg_fix" == "0" ]
	then
		warn "Warning: please install rbenv or run the doctor with --fix"
		return
	fi
	if [ "$arg_course" != "web" ]
	then
		# todo: is silent fail nice?
		return
	fi

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

function is_outdated_ruby() {
	local ruby_vers
	ruby_vers="$(ruby -e "puts RUBY_VERSION" 2>/dev/null)"

	if ! [[ "$ruby_vers" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]
	then
		warn "Warning: failed to parse ruby version '$ruby_vers'"
		# if we do not detect semver we count it as outdated
		# should technically even support but who knows truffleruby, mruby or jruby
		# some custom ruby version *might* fail in that case we claim its outdated
		return 1
	fi

	# macOS:
	# Usage: sort [-bcCdfigMmnrsuz] [-kPOS1[,POS2] ... ] [+POS1 [-POS2]] [-S memsize] [-T tmpdir] [-t separator] [-o outfile] [--batch-size size] [--files0-from file] [--heapsort] [--mergesort] [--radixsort] [--qsort] [--mmap] [--parallel thread_no] [--human-numeric-sort] [--version-sort] [--random-sort [--random-source file]] [--compress-program program] [file ...]

	if ! sort --help | grep -qE -- "([[:space:]]-V[^a-z]|--version-sort)"
	then
		warn "Warning: failed to check ruby version (sort -V not supported)"
		warn "         this is an issue with the doctor please report it here"
		warn ""
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return 1
	fi

	local latest
	# get latest version of the list "current" and "wanted"
	# sort -V supports semantic versioning sort
	# using tail -n1 we get the latest
	latest="$(printf '%s\n%s\n' "$(wanted_ruby_version)" "$ruby_vers" | sort -V | tail -n1)"

	# if we are the wanted version we are good
	# but also if we are more recent than the wanted version we are good
	[[ "$ruby_vers" != "$latest" ]] && return 0
	return 1
}

function check_brew_in_path_after_rbenv_init() {
	is_mac || return

	if [ ! -x "$(command -v brew)" ]
	then
		# this should never be hit
		# since the brew check is done before
		# but if it somehow happens then it is a different issue
		error "Error: please install brew and restart your terminal"
		exit 1
	fi
	if [ "$(command -v brew)" == "/usr/local/bin/brew" ]
	then
		# TODO: when getting hands on a mac again investigate
		#       where /usr/local/bin is added to path
		#       but im pretty sure it is before ~/.zshrc
		#       so rbenv should init just fine
		#       and we can pass this check
		return
	fi
	# it can either be
	#
	# eval "$(/opt/homebrew/bin/brew shellenv)"
	#
	# or directly
	#
	# PATH="$PATH:/opt/homebrew/bin"
	if grep "^[^#]*PATH=.*homebrew" ~/.zprofile || grep "^[^#]*eval.*/brew shellenv" ~/.zprofile
	then
		# zprofile is being loaded before zshrc
		# so if brew is in zprofile and rbenv in zshrc
		# it should be fine
		return
	fi
	if ! grep "^[^#]*PATH=.*homebrew" ~/.zshrc && ! grep "^[^#]*eval.*/brew shellenv" ~/.zshrc
	then
		# if the command brew is found
		# but we can not find the PATH manipulation in
		# zshrc or zprofile
		# then the doctor has a bug
		# maybe it is set in a .bashrc instead?
		error "Error: could not detect how brew is added to the path"
		error "       please report this issue here"
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		exit 1
	fi
	local brew_ln=-1
	local rbenv_ln
	if grep "^[^#]*PATH=.*homebrew" ~/.zshrc
	then
		brew_ln="$(grep -n "^[^#]*PATH=.*homebrew" ~/.zshrc | cut -d':' -f1)"
	else
		brew_ln="$(grep -n "^[^#]*eval.*/brew shellenv" ~/.zshrc | cut -d':' -f1)"
	fi
	# this should not happen
	# we should have checked the zshrc file first
	# shellcheck disable=SC2016
	if ! grep '^type -a rbenv > /dev/null && eval "$(rbenv init -)"' ~/.zshrc
	then
		error "Error: did not find rbenv in your ~/.zshrc"
		error "       please report this issue here"
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		exit 1
	fi
	# shellcheck disable=SC2016
	rbenv_ln="$(grep -n '^type -a rbenv > /dev/null && eval "$(rbenv init -)"' ~/.zshrc |
		cut -d':' -f1)"

	# if both brew and rbenv are loaded in zshrc
	# the order matters
	# if rbenv is loaded first it wont find the command rbenv
	# and thus not add the shims to the path
	if [ "$rbenv_ln" -lt "$brew_ln" ]
	then
		if [ "$arg_fix" == "1" ]
		then
			if is_arm
			then
				# shellcheck disable=SC2016
				echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
				eval "$(/opt/homebrew/bin/brew shellenv)"
				warn "Warning: please restart your terminal for ruby to work"
				exit 1
			else
				error "Error: fixing brew path is not supported on x86 yet"
				error "       feel free to report it here if you run into the issue"
				error "       https://github.com/ElvisDot/lewagon-setup/issues"
				exit 1
			fi
		else
			error "Error: brew is being added to the path after rbenv"
			error "       this causes a wrong ruby version to be loaded"
			error ""
			error "       your brew is here ${_color_YELLOW}~/.zshrc$_color_red line ${_color_YELLOW}$brew_ln"
			error "       your rbenv is here ${_color_YELLOW}~/.zshrc$_color_red line ${_color_YELLOW}$rbenv_ln"
			error ""
			error "       to fix it make sure brew is being loaded in the ~/.zprofile"
			error "       or open the zshrc file and make sure the brew line is above the rbenv line"
			error ""
			error "       or run the doctor with $_color_WHITE--fix"
			exit 1
		fi
	fi
}

function install_ruby() {
	local set_version
	set_version="$(rbenv versions | grep "set by.*.rbenv/version" | awk '{ print $2 }')"
	if [ "$set_version" != "" ] && [ "$set_version" == "$(wanted_ruby_version)" ]
	then
		# todo: should we throw an error or warning here?
		#       ruby is not found but rbenv claims to have set a version?
		test
	fi
	local got_wanted
	got_wanted="$(rbenv versions |
		tr -d '*' |
		awk '{ print $1 }' |
		grep "^$(wanted_ruby_version)$")"
	if [ "$got_wanted" == "$(wanted_ruby_version)" ]
	then
		if [ "$arg_fix" == "1" ]
		then
			log "Setting global ruby version to $_color_GREEN$(wanted_ruby_version)"
			rbenv global "$(wanted_ruby_version)"
		else
			warn "Warning: set your global ruby version to $(wanted_ruby_version)"
			warn "         using this command or run the doctor with $_color_WHITE--fix"
			warn ""
			warn "         ${_color_WHITE}rbenv global $(wanted_ruby_version)"
			warn ""
		fi
		return
	fi

	log "Installing ruby $(wanted_ruby_version) this can take a while"
	rbenv install "$(wanted_ruby_version)" || {
		error "Error: installing ruby version $(wanted_ruby_version) failed";
		error "       please report the issue here";
		error "       https://github.com/ElvisDot/lewagon-setup/issues";
		exit 1;
	}
	rbenv global "$(wanted_ruby_version)"
}

function check_ruby() {
	if [ ! -x "$(command -v rbenv)" ]
	then
		install_rbenv
		if [ ! -x "$(command -v rbenv)" ]
		then
			return
		fi
	fi
	if [ ! -x "$(command -v ruby)" ]
	then
		install_ruby
		return
	fi
	if [[ ! "$(command -v ruby)" =~ shims ]]
	then
		# if it finds an issue it exits
		# if it does not find an issue it silently returns
		check_brew_in_path_after_rbenv_init

		local rbenv_vers
		rbenv_vers="$(rbenv version | awk '{ print $1 }')"
		# if the rbenv version is set (so not the sys for empty version)
		# but ruby is not in the path that means rbenv thinks you got ruby
		# but ruby does not find it self in the shims PATH
		# that is a unknown bug to me
		if [ "$rbenv_vers" != "system" ] && [ "$rbenv_vers" == "" ]
		then
			error "Error: your ruby is not in the rbenv shims folder"
			error "       and the doctor does not know why"
			error "       if this happens to you please report the issue here"
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			exit 1
		fi
	fi

	if is_outdated_ruby
	then
		if [ "$arg_fix" == "1" ]
		then
			install_ruby
		else
			local ruby_vers
			ruby_vers="$(ruby -e "puts RUBY_VERSION" 2>/dev/null)"
			warn "Warning: your ruby version $_color_RED$ruby_vers$_color_yellow is outdated"
			warn "         the expected version is $_color_GREEN$(wanted_ruby_version)"
			warn "         To fix it try running these commands or the doctor with $_color_WHITE--fix"
			warn ""
			warn "         ${_color_WHITE}rbenv install $(wanted_ruby_version)"
			warn "         ${_color_WHITE}rbenv global $(wanted_ruby_version)"
		fi
	fi
}

function get_code_user_dir() {
	local dotfiles_dir=''
	for dir in ~/code/*/
	do
		[[ -d "$dir" ]] || return 1
		[[ "$(basename "$dir")" =~ [Ll]e[Ww]agon ]] && continue
		[[ ! -d "$dir"/dotfiles ]] && continue

		dotfiles_dir="$dir"
	done
	echo "$dotfiles_dir"
}

function run_dotfiles_install() {
	local dir
	local dotfiles_dir=''
	dotfiles_dir="$(get_code_user_dir)"
	if [ ! -d "$dotfiles_dir" ] || [ "$dotfiles_dir" == "" ]
	then
		error "Error: you are missing the dotfiles folder"
		error "       follow those steps again"
		error ""
		if is_mac
		then
			error "       https://github.com/lewagon/setup/blob/master/macos.md#dotfiles-standard-configuration"
		else
			error "       https://github.com/lewagon/setup/blob/master/windows.md#dotfiles-standard-configuration"
		fi
		error ""
		exit 1
	fi
	cd "$dotfiles_dir"/dotfiles || { error "Error: something went wrong"; exit 1; }
	local is_pass_note=0

	if grep "password is 123" ~/.zshrc
	then
		is_pass_note=1
	fi

	zsh install.sh

	if [ "$is_pass_note" == "1" ]
	then
		if ! grep "password is 123" ~/.zshrc
		then
			password_note >> ~/.zshrc
		fi
	fi
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
		[[ ! -f "$dotfile" ]] && broken_links=1

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
		run_dotfiles_install
	fi
	local found_dotfiles=0
	if [ "$(get_code_user_dir)" != "" ]
	then
		found_dotfiles=1
	fi
	# TODO: add comment explaining this line
	#       i do not understand it :D
	if [ ! -f ~/.zshrc ]
	then
		found_dotfiles=0
	fi
	if [ ! -f ~/.zprofile ] && is_data
	then
		# pyenv stuff is only crucial for data students
		error "Error: missing zprofile in dotfiles"
		found_dotfiles=0
	fi
	if [ "$found_dotfiles" == "1" ] && grep -q "rbenv init" ~/.zshrc
	then
		return 0
	fi
	return 1
}

function check_docker_installed() {
	if [ -x "$(command -v docker)" ]
	then
		return
	fi
	warn "Warning: docker is not installed"
	warn ""
	warn "         get it from here https://docs.docker.com/get-docker/"
	warn ""
	if is_windows
	then
		warn "         make sure to install it on your ${_color_GREEN}Linux$_color_yellow subsystem"
		warn "         not on your ${_color_RED}Windows$_color_yellow host system"
	fi
}

function check_docker_running() {
	# TODO: service docker start
	test
}

function check_docker() {
	check_docker_installed
	check_docker_running
}

function check_github_access() {
	if [ ! -x "$(command -v gh)" ]
	then
		error "Error: failed to find the github cli"
		error "       try to run the following command to install it"
		error ""
		if is_mac
		then
			error "       ${_color_WHITE}brew install gh"
		else
			error "       ${_color_WHITE}sudo apt install -y gh"
		fi
		error ""
		exit 1
	fi
	local is_logged_in=1
	if [ "$arg_full" == "1" ] && [ "$GITHUB_CI" == "" ]
	then
		local ssh_response
		ssh_response="$(ssh -T git@github.com)"
		if ! [[ "$ssh_response" =~ successfully\ authenticated ]]
		then
			is_logged_in=0
		fi
	else
		if [ ! -f ~/.config/gh/hosts.yml ]
		then
			is_logged_in=0
		elif ! grep -q "user:" ~/.config/gh/hosts.yml
		then
			is_logged_in=0
		fi
	fi

	if [ "$is_logged_in" == "1" ]
	then
		return
	fi

	if [ ! -f ~/.ssh/config ]
	then
		# todo: run dotfiles make sure they fix it
		warn "Warning: no ~/.ssh/config found"
	else
		if [ "$(grep -c Host ~/.ssh/config)" != "1" ] ||
			[ "$(grep -c IdentityFile ~/.ssh/config)" != "1" ]
		then
			warn "Warning: custom ~/.ssh/config found"
			warn "         this is fine as long as you know what you do"
		fi
		local ident
		while read -r ident
		do
			if [ ! -f "$ident" ]
			then
				# this is not very nice
				# but on my system it did not expand the tilde
				# other edge cases are not covered
				# but this should be working most of the time
				if [ ! -f "${ident/#~\//$HOME\/}" ]
				then
					# todo: auto fix this
					error "Error: your ~/.ssh/config points to a invalid identity file"
					error "       $ident"
					exit 1
				fi
			fi
		done < <(grep '^[[:space:]]*IdentityFile' ~/.ssh/config | awk '{ print $2 }')
	fi
	if [ ! -f ~/.ssh/id_ed25519 ]
	then
		# todo: do we do a gh auth login here or a ssh-keygen?
		error "Error: no LeWagon ssh key found"
		error "       try running this command"
		error ""
		error "       ${_color_WHITE}gh auth login"
		error ""
		exit 1
	fi
	local ssh_pub
	for ssh_pub in ~/.ssh/*.pub
	do
		[[ "$ssh_pub" == "id_ed25519.pub" ]] && continue

		if [ -f "$ssh_pub" ]
		then
			warn "Warning: unexpected ssh key found ${_color_YELLOW}$ssh_pub"
			warn "         this is fine if you know what you are doing"
		fi
	done

	# todo: autofix this or ask for reporting an issue
	error "Error: your git and github are not linked"
	error "       try running those commands"
	error ""
	error "       ${_color_WHITE}gh auth logout$_color_RESET"
	error "       ${_color_WHITE}gh auth login$_color_RESET"
	error ""
	exit 1
}

function fix_gitsome() {
	is_mac && return

	if [ ! -x "$(command -v curl)" ]
	then
		sudo apt-get install -y curl
	fi
	# gh command can conflict with gitsome if already installed
	sudo apt-get remove -y gitsome
	curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" |
		sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
	sudo apt-get update -y
}

function check_package_manager_programs() {
	local programs=()
	local prog
	if is_mac && is_data
	then
		for prog in ncdu xz
		do
			[[ -x "$(command -v "$prog")" ]] || programs+=("$prog")
		done
		# todo: check readline
	else # linux/windows
		for prog in unzip vim zsh tree
		do
			[[ -x "$(command -v "$prog")" ]] || programs+=("$prog")
		done
	fi

	for prog in git jq gh wget openssl tree
	do
		[[ -x "$(command -v "$prog")" ]] || programs+=("$prog")
	done

	if [[ ! -x "$(command -v convert)" ]]
	then
		programs+=(imagemagick)
	fi

	# none missing skip
	if (( ${#programs[@]} == 0 ))
	then
		return
	fi

	if is_mac
	then
		brew install "${programs[@]}"
	else
		for prog in "${programs[@]}"
		do
			if [ "$prog" == "gh" ]
			then
				fix_gitsome
				break
			fi
		done
		sudo apt-get install -y "${programs[@]}"
	fi
}

function brew_list_postgres() {
	brew list | grep postgres
}

function check_postgres_and_sqlite_installed() {
	if is_mac
	then
		if [ ! -x "$(command -v sqlite3)" ]
		then
			brew install sqlite
		fi
		if ! brew ls --versions "postgresql@$WANTED_POSTGRES_VERSION" > /dev/null
		then
			if [ "$arg_fix" == "1" ]
			then
				brew install "postgresql@$WANTED_POSTGRES_VERSION" libpq
				brew link --force libpq
				brew services start "postgresql@$WANTED_POSTGRES_VERSION"
				sleep 1 # give it time to start
			else
				warn "Warning: did not find postgresql@$WANTED_POSTGRES_VERSION"
				warn ""
				warn "         try running these commands to fix it:"
				warn ""
				warn "         ${_color_WHITE}brew install postgresql@$WANTED_POSTGRES_VERSION libpq"
				warn "         ${_color_WHITE}brew link --force libpq"
				warn "         ${_color_WHITE}brew services start postgresql@$WANTED_POSTGRES_VERSION"
				warn ""
				warn "         to fix it automatically"
				warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
			fi
		fi
		local postgres_versions
		postgres_versions="$(brew_list_postgres)"
		if [ "$(echo "$postgres_versions" | wc -l)" -gt 1 ]
		then
			warn "Warning: multiple postgres versions found"
			brew_list_postgres
		fi
	else # Windows/Linux
		if [ ! -x "$(command -v sqlite3)" ]
		then
			sudo apt-get install -y sqlite3 libsqlite3-dev
		fi
		if [ ! -x "$(command -v psql)" ]
		then
			sudo apt-get install -y postgresql postgresql-contrib libpq-dev build-essential
			if [ -f /etc/init.d/postgresql ]
			then
				sudo /etc/init.d/postgresql start
			elif [ -x "$(command -v systemctl)" ]
			then
				sudo systemctl start postgresql
			else
				error "Error: failed to start postgresql"
				error "       please report this issue here"
				error "       https://github.com/ElvisDot/lewagon-setup/issues"
				exit 1
			fi
		fi
	fi
}

function check_postgres_running_mac() {
	local postgres_status
	if ! postgres_status="$(brew services | grep postgres)"
	then
		warn "Warning: failed to get postgres status"
		return
	fi
	if [ "$postgres_status" == "" ]
	then
		warn "Warning: no postgres service installed"
		warn "         is postgres installed with brew?"
		warn ""
		warn "         this is probably a bug of the doctor it self"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if ! echo "$postgres_status" | awk '{ print $2 }' | grep -q started
	then
		warn "Warning: postgres is not running"
		warn ""
		warn "         $_color_WHITE$postgres_status"
		warn ""
		# check if a non brew postgres is blocking the port
		local blocked_port
		if ! blocked_port="$(lsof -i -P | grep ":5432 (LISTEN)")"
		then
			warn "Warning: failed to check for blocked port"
			return
		fi
		if [ "$blocked_port" == "" ]
		then
			return
		fi
		local blocking_pid
		if ! blocking_pid="$(echo "$blocked_port" | awk '{ print $2 }' | tail -n1)"
		then
			warn "Warning: failed to get blocking pid"
			return
		fi
		if ! [[ "$blocking_pid" =~ ^[0-9]+$ ]]
		then
			warn "Warning: got invalid pid '$blocking_pid'"
			warn ""
			warn "         this is a bug of the doctor it self"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		local blocking_proc_full
		if ! blocking_proc_full="$(ps ux -p "$blocking_pid" | tail -n1)"
		then
			warn "Warning: failed to get the process that blocks the postgres port"
			warn ""
			warn "         this is a bug of the doctor it self"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		warn "Warning: the postgres port is blocked by another process"
		warn "         do you have another postgres installed?"
		warn "         maybe a postgres docker container running?"
		warn "         try uninstalling or deactivating this process:"
		warn ""
		warn "         ${_color_red}$blocking_proc_full"
		warn ""
	fi
}

function check_postgres_running_linux() {
	if ! pidof -q systemd
	then
		# TODO: support sysvinit
		warn "Warning: failed to detect postgres health"
		return
	fi
	if [ ! -x "$(command -v systemctl)" ]
	then
		warn "Warning: failed to detect postgres health"
		return
	fi
	if ! systemctl is-active --quiet postgresql.service
	then
		if [ "$arg_fix" == "1" ]
		then
			log "starting postgresql service ..."
			sudo systemctl start postgresql.service
		else
			warn "Warning: postgresql service is not running"
			warn "         try starting postgres using this command"
			warn ""
			warn "         ${_color_WHITE}sudo systemctl start postgresql.service"
			warn ""
			warn "         to fix it automatically"
			warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
		fi
		return
	fi
}

function check_postgres_health() {
	if psql -lqt -U "$(whoami)" &> /dev/null
	then
		# we cann login and list databases using our user
		# assume everything is OK
		# to avoid prompting for sudo password on healthy systems
		return
	fi
	if ! sudo -u postgres psql -d postgres -c '\l' > /dev/null
	then
		warn "Warning: failed to list postgres databases"
		warn "         try running this command and check if there are any errors"
		warn ""
		warn "         ${_color_WHITE}sudo -u postgres psql -d postgres -c '\\l' > /dev/null"
		warn ""
		return
	fi
}

function check_postgres_role() {
	if psql -lqt -U "$(whoami)" &> /dev/null
	then
		# we cann login and list databases using our user
		# assume everything is OK
		# to avoid prompting for sudo password on healthy systems
		return
	fi
	if [ "$USER" == "root" ]
	then
		warn "Warning: can not check postgres role when running as root"
		return
	fi
	local username
	if ! username="$(id -u -n)"
	then
		warn "Warning: failed to check postgres role"
		return
	fi
	if [ "$USER" != "$username" ] || [ "$USER" == "" ]
	then
		warn "Warning: failed to check postgres role USER='$USER' username='$username'"
		return
	fi
	if [[ ! "$USER" =~ ^[a-z][-a-z0-9_]*$ ]]
	then
		warn "Warning: failed to check postgres role USER='$USER' (invalid name)"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if ! sudo -u postgres psql -d postgres -c "SELECT * FROM pg_roles WHERE rolname = '$USER';" | grep -q '1 row'
	then
		warn "Warning: missing postgresql role"
		warn "         try running this command"
		warn ""
		warn "         ${_color_WHITE}sudo -u postgres psql --command 'CREATE ROLE \"$(whoami)\" LOGIN createdb superuser;'"
		warn ""
	fi
}

function check_postgres_create_db() {
	if psql -U "$(whoami)" -lqt | grep -q lewagon_doc_test_db_delete_me
	then
		# TODO: should we warn here?
		# 	this means either the student created a db with this name
		# 	or the script failed to delete it
		# 	either way its a edge case and the system is probably healthy
		return
	fi
	if ! psql -U "$(whoami)" -d postgres -c 'CREATE DATABASE lewagon_doc_test_db_delete_me;' > /dev/null
	then
		warn "Warning: failed to create postgres database"
	fi
	if ! psql -U "$(whoami)" -d postgres -c 'DROP DATABASE lewagon_doc_test_db_delete_me;' > /dev/null
	then
		warn "Warning: failed to delete postgres database"
	fi
}

function check_database() {
	# TODO: persist postgres start command on wsl in zshrc
	check_postgres_and_sqlite_installed
	if is_mac
	then
		check_postgres_running_mac
	else
		check_postgres_running_linux
	fi
	check_postgres_health
	check_postgres_role
	check_postgres_create_db
}

function check_sip_mac() {
	# SIP - System Integrity Protection
	#
	# https://www.kolide.com/features/checks/mac-system-integrity-protection
	# https://github.com/rbenv/ruby-build/issues/2073#issuecomment-1335651657
	#
	# SIP should be on for security
	# and in some niche edge cases
	# SIP being off might also break the ruby build
	# but also for the data camp is worth an alert
	if [ ! -x "$(command -v csrutil)" ]
	then
		# should we throw a warning here?
		return
	fi
	if [ "$(csrutil status)" == "System Integrity Protection status: enabled." ]
	then
		return
	fi
	warn "Warning: System Integrity Protection is OFF"
	warn "         please turn on SIP following this article"
	warn "         https://www.kolide.com/features/checks/mac-system-integrity-protection"
}

function check_github_name_matches() {
	# check if the ssh key is logged in
	# to the same github username
	# as the folder name ~/code/username
	#
	# this might not break the setup but
	# is a good indicator something is weird
	local code_dir_username
	code_dir_username="$(basename "$(get_code_user_dir)")"
	if [ "$code_dir_username" == "" ]
	then
		return 1
	fi
	local github_username=''
	if [[ "$(ssh -T git@github.com 2>&1)" =~ Hi\ (.*)! ]]
	then
		github_username="${BASH_REMATCH[1]}"
	fi
	if [ "$github_username" == "" ]
	then
		return 1
	fi
	if [ "$github_username" != "$code_dir_username" ]
	then
		warn "Warning: there are two usernames found"
		warn "         one in your ~/code dir: $_color_RED$code_dir_username"
		warn "         one  authed on  github: $_color_RED$github_username"
		return 0
	fi
	return 1
}

function check_git_and_github_email_match() {
	local github_email
	local git_email
	if ! gh auth status &> /dev/null
	then
		return
	fi
	github_email="$(gh api user | jq -r '.email')"
	if [ "$github_email" == "null" ]
	then
		# TODO: find another way to check
		#       if it can't find the email here
		#       this happens when the user
		#       sets the email to private in the account settings
		return
	fi
	git_email="$(git config --global user.email)"
	if [ "$github_email" == "$git_email" ]
	then
		return
	fi
	warn "Warning: your git email does not match your github one"
	warn "            git: $_color_RED$git_email"
	warn "         github: $_color_RED$github_email"
	if [ "$arg_fix" == "1" ]
	then
		log "updating git email to be '$github_email' ..."
		git config --global user.email "$github_email"
		local code_dir_username
		code_dir_username="$(basename "$(get_code_user_dir)")"
		local challenges_dir="$HOME/code/$code_dir_username/fullstack-challenges"
		if [ -d "$challenges_dir" ]
		then
			cd "$challenges_dir" || return
			git commit --allow-empty -m "New commit with fixed email"
			git push origin master
		fi
	else
		warn ""
		warn "         try running these commands to fix it:"
		warn ""
		warn "         ${_color_WHITE}cd ~/code/*/fullstack-challenges"
		warn "         ${_color_WHITE}git config --global user.email \"$github_email\""
		warn "         ${_color_WHITE}git commit --allow-empty -m \"New commit with fixed email\""
		warn "         ${_color_WHITE}git push origin master"
		warn ""
		warn "         to fix it automatically"
		warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
	fi
}

function check_ready_commit_email() {
	# Kitt is waiting for the student
	# to push a commit with the correct email
	# set in the fullstack-challenges repo
	if ! gh auth status &> /dev/null
	then
		return
	fi
	local ready_email
	local github_email
	local code_dir_username
	code_dir_username="$(basename "$(get_code_user_dir)")"
	local challenges_dir="$HOME/code/$code_dir_username/fullstack-challenges"
	if [ ! -d "$challenges_dir" ]
	then
		return
	fi
	cd "$challenges_dir" || return
	github_email="$(gh api user | jq -r '.email')"
	if [ "$github_email" == "null" ]
	then
		# email is private no need to compare
		# TODO: find a way to get email anyways
		return
	fi
	ready_email="$(
		git log \
			-s \
			--pretty=format:'%ae %s' \
			--perl-regexp \
			--grep "(New commit with fixed email|I am so ready)" | \
			head -n1 | \
			awk '{print $1 }')"
	if [ "$ready_email" == "$github_email" ]
	then
		return
	fi
	warn 'Warning: your github email is not in the "I am so ready" commit'
	warn "         ready  email: $_color_RED$ready_email"
	warn "         github email: $_color_RED$github_email"
	if [ "$arg_fix" == "1" ]
	then
		log "Sending ready commit with email '$github_email' ..."
		git config --global user.email "$github_email"
		git commit --allow-empty -m "New commit with fixed email"
		git push origin master
	else
		warn ""
		warn "         try running these commands to fix it:"
		warn ""
		warn "         ${_color_WHITE}cd ~/code/*/fullstack-challenges"
		warn "         ${_color_WHITE}git config --global user.email \"$github_email\""
		warn "         ${_color_WHITE}git commit --allow-empty -m \"New commit with fixed email\""
		warn "         ${_color_WHITE}git push origin master"
		warn ""
		warn "         to fix it automatically"
		warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
	fi
}

function check_github_org_invite_accept() {
	if ! gh auth status &> /dev/null
	then
		return
	fi
	if gh api user/orgs | jq '.[].login' | grep -qi '"lewagon"'
	then
		return
	fi
	warn "Warning: lewagon organisation not found in your github account"
	warn "         open the following link in your browser and accept"
	warn "         the invite"
	warn ""
	warn "         https://github.com/orgs/lewagon/invitation"
	warn ""
	warn "         if there is no invite ask your batch manager"
}

function assert_num_file_lines() {
	local filename="$1"
	local min_lines="$2"
	local max_lines="$3"
	local file_lines
	[[ -f "$filename" ]] || return

	file_lines="$(wc -l "$filename" | awk '{ print $1 }')"
	if [ "$file_lines" -lt "$min_lines" ]
	then
		warn "Warning: there are less lines in $filename than expected"
		warn "         expected at least: $min_lines"
		warn "                       got: $file_lines"
	fi
	if [ "$file_lines" -gt "$max_lines" ]
	then
		warn "Warning: there are more lines in $filename than expected"
		warn "         expected at most: $max_lines"
		warn "                      got: $file_lines"
	fi
}

function assert_num_dupe_lines() {
	local filename="$1"
	local max_dupes="$2"
	[[ -f "$filename" ]] || return

	# TODO: find portable `uniq -D` for mac
	#       https://github.com/ElvisDot/lewagon-setup/issues/4
	is_mac && return

	local num_dupes
	num_dupes="$(sort "$filename" | uniq -D | awk NF | wc -l)"
	if [ "$num_dupes" -gt "$max_dupes" ]
	then
		warn "Warning: there are $_color_RED$num_dupes$_color_yellow duplicated lines in"
		warn "         the file $filename"
	fi
}

function underline_str() {
	# usage: underline_str string [offset]
	# arguments:
	# 	string - the string to be underlined (only used to count the length)
	# 	offset - if no offset is given it underlines the whole string
	# 		 if a offset is given it only underlines at the offset
	# 		 and one before and after it
	# example:
	# 	underline_str hello
	# 	returns ^^^^^
	#
	#	underline_str hello 2
	#	returns  ^^^
	local str="$1"
	local offset="$2"
	local is_offset=0
	if [[ "$offset" =~ ^[0-9]+$ ]]
	then
		is_offset=1
	fi
	local i
	for ((i=0;i<${#str};i++))
	do
		if [ "$is_offset" != "1" ]
		then
			printf '^'
			continue
		fi
		if [ "$i" == "$((offset-1))" ] || [ "$i" == "$offset" ] || [ "$i" == "$((offset+1))" ]
		then
			printf '^'
		else
			printf ' '
		fi
	done
	printf '\n'
}

function check_zshrc_plugins() {
	local num_plugin_lists
	[[ -f ~/.zshrc ]] || return

	num_plugin_lists="$(grep -c "^[[:space:]]*plugins=" ~/.zshrc)"
	if [ "$num_plugin_lists" == "0" ]
	then
		warn "Warning: the ${_color_WHITE}plugins=()$_color_yellow list is missing in your ~/.zshrc"
		warn "         you might be missing out on some fancy plugins Le Wagon recommends"
		return
	elif [ "$num_plugin_lists" -gt "1" ]
	then
		warn "Warning: the ${_color_WHITE}plugins=()$_color_yellow list"
		warn "         is found $_color_RED$num_plugin_lists$_color_yellow times in your ~/.zshrc"
		warn "         it should only be there once"
		return
	fi
	local plugin_list
	plugin_list="$(grep "[[:space:]]*plugins=" ~/.zshrc)"
	plugin_list_line="$(grep -n "[[:space:]]*plugins=" ~/.zshrc | cut -d ':' -f1)"
	if [[ "$plugin_list" =~ ^[:space:]*plugins=\([^#]+\)[^#]+ssh ]]
	then
		local paren_offset=''
		if ! paren_offset="$(echo "$plugin_list" | grep -b -o \) | cut -d':' -f1 | head -n1)"
		then
			paren_offset=''
		fi
		warn "Warning: make sure ssh-agent is inside of the ${_color_WHITE}plugins=()$_color_yellow list"
		warn "         it should be between the parenthesis not after the closing one"
		warn "         please have a look at the $_color_RED$HOME/.zshrc$_color_yellow file"
		warn "         in line $_color_RED$plugin_list_line"
		warn ""
		warn "         $plugin_list"
		warn -n "         "
		underline_str "$plugin_list" "$paren_offset"
		warn ""
	fi
	# Using bash eval to check the zshrc plugin list
	# is technically not correct.
	# But it does the job to detect most of the student
	# fckups. For example parenthesis missplacement.
	if ! eval "$plugin_list" &> /dev/null;
	then
		warn "Warning: there might be a syntax error in the ${_color_WHITE}plugins=()$_color_yellow list"
		warn "         please have a look at the $_color_RED$HOME/.zshrc$_color_yellow file"
		warn "         in line $_color_RED$plugin_list_line"
		warn ""
		warn "         $plugin_list"
		warn -n "         "
		underline_str "$plugin_list"
		warn ""
	fi
}

function check_zshrc_contents() {
	[[ -f ~/.zshrc ]] || return

	assert_num_file_lines ~/.zshrc 60 110
	assert_num_dupe_lines ~/.zshrc 6
	check_zshrc_plugins
}

function check_pyenv_in_zprofile() {
	# no need to alert web students about this
	is_data || return

	# https://github.com/lewagon/dotfiles/blob/master/zprofile
	# keep up to date with this
	#
	# matching this line
	# type -a pyenv > /dev/null && eval "$(pyenv init --path)"
	#
	# supports custom indent
	if grep -q '^[[:space:]]*type -a pyenv' ~/.zprofile
	then
		return
	fi
	warn "Warning: missing pyenv init in ~/.zprofile"

}

function check_zprofile_contents() {
	[[ -f ~/.zprofile ]] || return

	assert_num_file_lines ~/.zprofile 3 15
	assert_num_dupe_lines ~/.zprofile 5
	check_pyenv_in_zprofile
}

function check_node_version() {
	if [ ! -x "$(command -v node)" ]
	then
		# TODO: install it?
		return
	fi
	if ! grep -F '.nvm' | command -v node
	then
		warn "Warning: node does not seem to be installed with nvm"
		return
	fi

	# TODO: uncomment this as soon as the version check is future proof

	# local node_version
	# local expected_version="$(wanted_node_version)"
	# node_version="$(node -v)"
	# if [ "$node_version" != "$expected_version" ]
	# then
	# 	warn "Warning: expected node version '$expected_version' got '$node_version'"
	# fi
}

function persist_brew_in_path() {
	is_mac || return

	# hardcoding .zprofile here is a conscious decision
	# it leaves non zsh shell setups in a broken state
	# such as bash, fish etc
	#
	# this script is not intended to fix/support custom setups
	# but to ensure this device is setup the le wagon intended way
	local shell_profile
	shell_profile="${HOME}/.zprofile"

	if ! grep -qs "eval \"\$(${HOMEBREW_PREFIX}/bin/brew shellenv)\"" "${shell_profile}"
	then
		local fix_brew_cmd
		fix_brew_cmd="(echo; echo 'eval \"\$(${HOMEBREW_PREFIX}/bin/brew shellenv)\"') >> ${shell_profile}"
		if [ "$arg_fix" == "1" ]
		then
			log "persisting brew in PATH ..."
			warn "Warning: you need to restart your terminal"
			warn "         for brew to work properly"
			eval "$fix_brew_cmd"
		else
			warn "Warning: brew does not seem presistet in your PATH"
			warn "         verify that the command ${_color_WHITE}brew$_color_yellow still works"
			warn "         when opening a new terminal tab. If it does not you can fix it using"
			warn "         this command or run the doctor with $_color_WHITE--fix"
			warn ""
			warn "         ${_color_WHITE}$fix_brew_cmd"
			warn ""
		fi
	fi
}

function check_zscaler_ssl() {
	if [ ! -x "$(command -v openssl)" ]
	then
		warn "Warning: could not check zscaler because openssl is not installed"
		return
	fi
	if [ ! -x "$(command -v timeout)" ]
	then
		warn "Warning: could not check zscaler because timeout is not installed"
		warn "         to fix this please install core utils"
		return
	fi
	# https://www.zscaler.com/
	# I do not know what they do and also do not want to
	# but they kicked digicert out of the ca chain
	# which breaks all tls encrypted connections to
	# github.com on wsl
	#
	# this is how the output on a broken system looks like
	# $ openssl s_client -connect github.com:443
	# CONNECTED(00000005)
	# depth=2 C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalertwo.net), emailAddress = support@zscaler.com
	# verify error:num=20:unable to get local issuer certificate
	# ---
	# Certificate chain
	# 0 s:C = US, ST = California, L = San Francisco, O = "GitHub, Inc.", CN = github.com
	# i:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = "Zscaler Intermediate Root CA (zscalertwo.net) (t) "
	# 1 s:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = "Zscaler Intermediate Root CA (zscalertwo.net) (t) "
	# i:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalertwo.net), emailAddress = support@zscaler.com
	# 2 s:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalertwo.net), emailAddress = support@zscaler.com
	# i:C = US, ST = California, L = San Jose, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Root CA, emailAddress = support@zscaler.com
	# ---
	#
	#
	# this is how it should look like on a healthy system:
	#
	# CONNECTED(00000003)
	# depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
	# verify return:1
	# depth=1 C = US, O = DigiCert Inc, CN = DigiCert TLS Hybrid ECC SHA384 2020 CA1
	# verify return:1
	# depth=0 C = US, ST = California, L = San Francisco, O = "GitHub, Inc.", CN = github.com
	# verify return:1
	# ---
	# Certificate chain
	# 0 s:C = US, ST = California, L = San Francisco, O = "GitHub, Inc.", CN = github.com
	# i:C = US, O = DigiCert Inc, CN = DigiCert TLS Hybrid ECC SHA384 2020 CA1
	# 1 s:C = US, O = DigiCert Inc, CN = DigiCert TLS Hybrid ECC SHA384 2020 CA1
	# i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
	# ---

	# the timeout is very much needed
	# because this operation is super slow at all times
	# lets rather miss out on this warning on a very slow machine
	# than slow down the doctor by 15s for every windows machine
	if timeout 1 openssl s_client -connect github.com:443 2>&1 | grep -q Zscaler
	then
		warn "Warning: Zscaler seems to be messing with your connection"
		warn "         if connecting to github.com works fine ignore this error"
		warn "         and report it as false positive here please"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		warn "         if gh auth or other github operations fail"
		warn "         please turn off Zscaler on your windows machine"
		warn ""
	fi
}

function check_if_custom_anti_virus_is_running() {
	local anti_viruses=''
	if ! anti_viruses="$(
		powershell.exe \
			"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct" \
			| grep displayName
	)"
	then
		warn "Warning: failed to list anti viruses"
		return
	fi
	# allow windows defender
	# this is the output on a system with windows defender running
	# displayName              : Windows Defender
	anti_viruses="$(echo "$anti_viruses" | grep -v "Windows Defender" | awk NF)"

	if [ "$anti_viruses" == "" ]
	then
		return
	fi

	# indent to look nice in the warning message
	anti_viruses="$(echo "$anti_viruses" | awk '{ print "         " $0 }')"
	warn "Warning: you have the following anti virus tools running"
	warn "         if you have issues with the setup"
	warn "         try stopping and or uninstalling those"
	warn ""
	warn "$anti_viruses"
}

function check_windows_anti_virus() {
	check_zscaler_ssl
	check_if_custom_anti_virus_is_running
}

function check_disk_space() {
	# only check the / partition

	local avail
	if is_mac
	then
		if ! avail="$(df -h /System/Volumes/Data | awk '{ print $4 }' | tail -n1)"
		then
			warn "Warning: failed to get free disk space"
			return
		fi
	else
		if ! avail="$(df -h 2>/dev/null | grep ' /$' | awk '{ print $4 }')"
		then
			warn "Warning: failed to get free disk space"
			return
		fi
	fi
	if [[ "$avail" =~ ^[0-9]+M$ ]] || [[ "$avail" =~ ^[0-9]+K$ ]]
	then
		warn "Warning: detected too little free disk space $avail"
	elif [[ "$avail" =~ ^([0-9]+)Gi?$ ]]
	then
		local avail_gb
		avail_gb="${BASH_REMATCH[1]}"
		if [ "$avail_gb" -lt "$MIN_DISK_SPACE_GB" ]
		then
			warn "Warning: you only seem to have $avail_gb GB free disk space"
			warn "         it is recommended to have more than $MIN_DISK_SPACE_GB GB"
		fi
	else
		warn "Warning: failed to detect available disk space"
	fi
}

function check_rvm() {
	if [ -d ~/.rvm ]
	then
		warn "Warning: rvm folder found ~/.rvm"
		warn "         rvm might be conflicting with rbenv"
		warn "         the Le Wagon setup recommends rbenv over rvm"
		warn "         if you know what you are doing"
		warn "         this is fine"
		return
	fi
	if [ -x "$(command -v rvm)" ]
	then
		warn "Warning: rvm executable found"
		warn "         rvm might be conflicting with rbenv"
		warn "         the Le Wagon setup recommends rbenv over rvm"
		warn "         if you know what you are doing"
		warn "         this is fine"
		return
	fi
}

function check_mac_ports() {
	if [ ! -x "$(command -v port)" ]
	then
		return
	fi
	if ! port help 2>&1 | grep -qi MacPorts
	then
		return
	fi
	warn "Warning: port command found"
	warn "         do you have mac ports installed?"
	warn "         this can conflict with homebrew"
}

function check_asdf_ruby() {
	if [ ! -d ~/.asdf/plugins/ruby/ ]
	then
		return
	fi
	warn "Warning: ${_color_YELLOW}asdf$_color_yellow ruby plugin found"
	warn "         asdf is a competitor of rbenv"
	warn "         Le Wagon recommends rbenv"
	warn "         if your ruby is working"
	warn "         and you know what you are doing this is fine."
}

function check_asdf_python() {
	if [ ! -d ~/.asdf/plugins/python/ ]
	then
		return
	fi
	warn "Warning: ${_color_YELLOW}asdf$_color_yellow python plugin found"
	warn "         asdf is a competitor of pyenv"
	warn "         Le Wagon recommends pyenv"
	warn "         if your python is working"
	warn "         and you know what you are doing this is fine."
}

function check_rails_version() {
	if [ ! -x "$(command -v rails)" ]
	then
		return
	fi
	if ! [[ "$(rails -v)" =~ Rails\ ([0-9])\..* ]]
	then
		warn "Warning: failed to parse rails version"
		warn ""
		warn "         $_color_YELLOW$(rails -v)"
		warn ""
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	local major_rails_version
	major_rails_version="${BASH_REMATCH[1]}"
	if [ "$major_rails_version" -ge "$WANTED_RAILS_MAJOR_VERSION" ]
	then
		return
	fi
	if [ "$arg_fix" == "1" ]
	then
		if ! which gem | grep -qF rbenv/shims
		then
			warn "Warning: failed to install rails"
			warn "         because the gem command is not"
			warn "         installed via rbenv"
			return
		fi
		gem install rails
		return
	fi
	warn "Warning: your rails version $_color_RED$major_rails_version$_color_yellow is outdated"
	warn "         the expected version is $_color_GREEN$WANTED_RAILS_MAJOR_VERSION"
	warn ""
	warn "         reinstalling the gem should fix it:"
	warn ""
	warn "         ${_color_WHITE}gem install rails"
	warn ""
	warn "         or run the doctor with $_color_WHITE--fix"
	warn ""
}

function check_git_init_in_fullstack_challenges() {
	# if a student types `git init`
	# in the challenges folder
	# can happen on setup day while testing git
	# it overwrites the outer git folder
	# and breaks commands such as `git pull`
	# and `git push` because the remotes are gone
	local git_repos
	local code_dir_username
	code_dir_username="$(basename "$(get_code_user_dir)")"
	local challenges_dir="$HOME/code/$code_dir_username/fullstack-challenges"
	[[ -d "$challenges_dir" ]] || return
	cd "$challenges_dir" || return

	if ! git_repos="$(find . -type d -name .git)"
	then
		warn "Warning: failed to check git repos in fullstack-challenges"
		warn "         this is a issue with the doctor. Please report it here:"
		warn ""
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if [ "$git_repos" == "./.git" ]
	then
		# all good
		return
	fi

	if [ ! -d ./.git ]
	then
		warn "Warning: missing git folder in fullstack-challenges folder"
		warn "         $(pwd)"
	fi

	if [ "$git_repos" != "" ]
	then
		warn "Warning: unexpected git repositories found in"
		warn "         your fullstack-challenges folder"
		warn ""
		warn "         your challenges dir:"
		warn "           $_color_GREEN$(pwd)"
		warn ""
		warn "         unexpected git folders:"
		local git_repo
		while IFS= read -r -d '' git_repo
		do
			[[ "$git_repo" == './.git' ]] && continue

			warn "           $_color_RED$git_repo$_color_RESET"
		done < <(find . -type d -name .git -print0)
		warn ""
		warn "         This breaks ${_color_WHITE}git push$_color_yellow and other"
		warn "         git commands in these folders. The fix is to"
		warn "         delete these git repos like so:"
		warn ""
		while IFS= read -r -d '' git_repo
		do
			[[ "$git_repo" == './.git' ]] && continue

			local full_path_git_repo
			# readlink -f can fail
			# then fallback to a cd suggestion instead
			if ! full_path_git_repo="$(readlink -f "$git_repo")"
			then
				warn "           ${_color_WHITE}cd $(pwd) && rm -rf $full_path_git_repo$_color_RESET"
				continue
			fi
			warn "           ${_color_WHITE}rm -rf $full_path_git_repo$_color_RESET"
		done < <(find . -type d -name .git -print0)
		warn ""
	fi
}

function main() {
	check_colors
	device_info
	check_basics
	check_disk_space
	if is_mac
	then
		check_brew
		check_mac_ports
		check_sip_mac
	elif is_windows
	then
		check_windows_anti_virus
	fi
	detect_bootcamp
	check_vscode
	check_package_manager_programs
	check_github_access
	if ! check_dotfiles
	then
		# do not continue if no dotfiles are found
		error "Error: missing dotfiles aborting"
		exit 1
	fi
	if ! check_github_name_matches
	then
		# those two checks
		# assume you are authed
		# to the correct github account
		# using the gh cli
		if is_web
		then
			check_github_org_invite_accept
		fi
		check_git_and_github_email_match
	fi
	check_zshrc_contents
	check_zprofile_contents
	if is_web
	then
		check_ruby
		check_rvm
		check_asdf_ruby
		check_rails_version
		check_database
		check_ready_commit_email
		check_git_init_in_fullstack_challenges
	elif is_data
	then
		check_docker
		check_asdf_python
	fi
	if [ "$num_errors" == "0" ] && [ "$num_warnings" == "0" ]
	then
		log "✅$_color_GREEN your system is healthy"
	else
		log "Summary warnings: $num_warnings errors: $num_errors"
	fi
}

main
