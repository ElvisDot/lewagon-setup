#!/usr/bin/env bash

_color_RESET="\e[0m"
_color_BLACK="\e[1;30m"
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
_color_magenta="\e[0;35m"
# _color_cyan="\e[0;36m"
# _color_white="\e[0;37m"

# Background
# _color_bg_black="\033[40m"       # Black
# _color_bg_red="\033[41m"         # Red
# _color_bg_green="\033[42m"       # Green
# _color_bg_yellow="\033[43m"      # Yellow
# _color_bg_blue="\033[44m"        # Blue
# _color_bg_purple="\033[45m"      # Purple
# _color_bg_cyan="\033[46m"        # Cyan
_color_bg_white="\033[47m"         # White

arg_verbose=0
arg_full=0
arg_fix=0
arg_course=""
arg_unix_name=""

bootcamp=unkown

num_warnings=0
num_errors=0

g_vscode_extensions_cache=''
g_github_ssh_username=''
g_github_cli_username=''
g_github_cli_email=''
g_gh_auth_status=''
# g_ipv4_ok=0 # costs time to check and is not very interesting anyways
g_ipv6_ok=0

MIN_DISK_SPACE_GB=10

WANTED_RUBYGEMS_VERSION=3.5.9
WANTED_RAILS_MAJOR_VERSION=7
WANTED_WSL_VERSION=2
WANTED_POSTGRES_VERSION=15
WANTED_NODE_VERSION='16.15.1'
WANTED_RUBY_VERSION='3.1.2'
WANTED_PYTHON_VERSION='3.10.6'
WANTED_DOTFILES_SHA='adf05d5bffffc08ad040fb9c491ebea0350a5ba2'
# bash arrays would be nicer code but spaced strings are POSIX
WANTED_VSCODE_EXTENSIONS_WEB="ms-vscode.sublime-keybindings emmanuelbeziat.vscode-great-icons github.github-vscode-theme MS-vsliveshare.vsliveshare rebornix.ruby dbaeumer.vscode-eslint Rubymaniac.vscode-paste-and-indent alexcvzz.vscode-sqlite anteprimorac.html-end-tag-labels"

# unix ts generated using date '+%s'
# update it using ./scripts/update.sh
LAST_DOC_UPDATE=1714710963
MAX_DOC_AGE=300

is_dotfiles_old=0
is_vscode_healthy=0

if [ "${BASH_VERSINFO:-0}" -lt 3 ]
then
	echo "Error: your bash version $BASH_VERSION is too old"
	exit 1
fi

# check self deprecation
# if this script is not being maintained
# it gets outdated
function is_doc_deprecated() {
	local now
	if ! now="$(date '+%s')"
	then
		return 0
	fi
	local days
	days="$(( (now - LAST_DOC_UPDATE) / 86400 ))"
	if [ "$days" -gt "$MAX_DOC_AGE" ]
	then
		return 0
	fi
	return 1
}

UNAME_MACHINE="unkown"
HOMEBREW_PREFIX="/usr/local"
if [ -f /usr/bin/uname ]
then
	UNAME_MACHINE="unkown"
else
	# straight copy from the homebrew install script
	# https://github.com/Homebrew/install/blob/95648ef45c8d59a44fa4ab8f29cdcf17d6ec48ac/install.sh#L127-L138
	UNAME_MACHINE="$(/usr/bin/uname -m)"
	if [ "${UNAME_MACHINE}" = "arm64" ]
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
	if is_doc_deprecated
	then
		local node_version
		if node_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/windows.md | grep 'nvm install ' | awk '{ print $3 }')"
		then
			if [[ "$node_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
			then
				WANTED_NODE_VERSION="$node_version"
			fi
		fi
	fi
	echo "$WANTED_NODE_VERSION"
}

function wanted_ruby_version() {
	if is_doc_deprecated
	then
		local ruby_version
		if ruby_version="$(curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep "^REQUIRED_RUBY_VERSION" | cut -d'"' -f2)"
		then
			if [ "$ruby_version" != "" ]
			then
				WANTED_RUBY_VERSION="$ruby_version"
			fi
		fi
	fi
	echo "$WANTED_RUBY_VERSION"
}

function parse_args() {
	local flags
	local flag
	local arg
	while true
	do
		[ "$#" -lt "1" ] && break

		arg="$1"
		shift

		if [ "${arg::2}" = "--" ]
		then
			if [ "$arg" = "--help" ]
			then
				show_help
				exit 0
			elif [ "$arg" = "--full" ]
			then
				arg_full=1
			elif [ "$arg" = "--verbose" ]
			then
				arg_verbose=1
			elif [ "$arg" = "--fix" ]
			then
				arg_fix=1
			elif [ "$arg" = "--course" ]
			then
				arg_course="$1"
				bootcamp="$1"
				shift

				if [ "$bootcamp" != "web" ] && [ "$bootcamp" != "data" ]
				then
					echo "usage: $(basename "$0") --course <web|data>"
					exit 1
				fi
			elif [ "$arg" = "--unix-name" ]
			then
				arg_unix_name="$1"
				shift

				if [ "$arg_unix_name" = "" ]
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
		elif [ "${arg::1}" = "-" ]
		then
			flags="${arg:1}"
			while IFS= read -n1 -r flag
			do
				if [ "$flag" = "v" ]
				then
					arg_verbose="$((arg_verbose+1))"
				elif [ "$flag" = "h" ]
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
	if [ "$NO_COLOR" = "" ] && [ -t 1 ] && [[ "$TERM" =~ color ]]
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
	printf '%b[%b-%b]%b %b%b\n' "$_color_WHITE" "$_color_RED" "$_color_WHITE" "$_color_red" "$msg" "$_color_RESET" 1>&2
}

function warn() {
	local msg="$1"
	local nl='\n'
	if [ "$msg" = "-n" ]
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
	local newline='\n'
	if [ "$1" = "-n" ]
	then
		newline=''
		shift
	fi
	printf '%b[*]%b %b%b%b' "$_color_WHITE" "$_color_RESET" "$1" "$_color_RESET" "$newline"
}

function okay() {
	printf '%b[%b+%b]%b %b%b\n' "$_color_WHITE" "$_color_GREEN" "$_color_WHITE" "$_color_RESET" "$1" "$_color_RESET"
}

function dbg() {
	[ "$arg_verbose" -gt "0" ] || return

	local newline='\n'
	if [ "$1" = "-n" ]
	then
		newline=''
		shift
	fi
	printf '%b[*]%b %b%b%b' "$_color_WHITE" "$_color_RESET" "$1" "$_color_RESET" "$newline"
}

function dbg_echo() {
	[ "$arg_verbose" -gt "0" ] || return

	local newline='\n'
	if [ "$1" = "-n" ]
	then
		newline=''
		shift
	fi
	printf '%b%b%b%b' "$_color_WHITE" "$1" "$_color_RESET" "$newline"
}

function check_http() {
	local arg=''
	local host=''
	local arg_family=''
	local ip_flag=''
	for arg in "$@"
	do
		if [ "$host" = "" ]
		then
			host="$arg"
		elif [ "$arg" = "--ipv4" ]
		then
			arg_family=ipv4
		elif [ "$arg" = "--ipv6" ]
		then
			arg_family=ipv6
		else
			error "Error: unsupported arg for check_http '$arg'"
			error "       this is an issue with the doctor please report it here"
			error ""
			error "       https://github.com/ElvisDot/lewagon-setup/issues"
			return 1
		fi
	done
	if [ -x "$(command -v curl)" ]
	then
		[ "$arg_family" = "ipv4" ] && ip_flag='-4'
		[ "$arg_family" = "ipv6" ] && ip_flag='-6'
		curl $ip_flag --max-time 10 "$host" &>/dev/null && return 0
	elif [ -x "$(command -v wget)" ]
	then
		[ "$arg_family" = "ipv4" ] && ip_flag='--inet4-only'
		[ "$arg_family" = "ipv6" ] && ip_flag='--inet6-only'
		wget $ip_flag --timeout 10 --tries 1 "$host" &>/dev/null && return 0
	fi
	return 1
}

function check_ssl() {
	local host
	local hosts=(https://github.com https://lewagon.com https://google.com)
	local failed=0
	for host in "${hosts[@]}"
	do
		log -n "testing https connection to $_color_WHITE$host$_color_RESET"
		if check_http "$host"
		then
			echo -e "$_color_GREEN\tOK"
		else
			echo -e "$_color_RED\tFAILED"
			failed=1
		fi
	done
	[ "$failed" = 1 ] && warn "Warning: Could not establish SSL connection!"
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
	local is_fatal=0
	for host in "${hosts[@]}"
	do
		log -n "testing http connection to $_color_WHITE$host$_color_RESET"
		if check_http "$host"
		then
			echo -e "$_color_GREEN\tOK"
		else
			echo -e "$_color_RED\tFAILED"
			[ "$host" = "http://github.com" ] && is_fatal=1
		fi
	done
	# google and lewagon can fail
	# but the doctor script depends on connectivity to github
	if [ "$is_fatal" = "1" ]
	then
		error "Error: could not ping 8.8.8.8 or do a http request to github.com"
		error "       is your internet working?"
		exit 1
	fi
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

function pwsh() {
	local powershell_command="$1"
	if [ ! -x "$(command -v powershell.exe)" ]
	then
		error "Error: powershell.exe not found" 1>&2
		exit 1
	fi
	if ! powershell.exe -c "$powershell_command"
	then
		exit 1
	fi
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
	echo 'echo "To remove this note run this command:"'
	echo 'echo ""'
	echo 'echo "  code ~/.zshrc"'
	echo 'echo ""'
}

function check_user_windows() {
	is_windows || return
	if [[ "$UID" != "0" ]] && [[ "$EUID" != "0" ]]
	then
		return
	fi

	if [ "$arg_fix" = "1" ]
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
	if [ "$zsh_path" = "" ]
	then
		sudo apt-get install -y zsh
	fi
	if [ "$zsh_path" = "" ]
	then
		error "Error: you need zsh installed"
		exit 1
	fi

	username="$(detect_user)"
	if [ "$username" = "" ]
	then
		if [ "$arg_unix_name" = "" ]
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

	pwsh "ubuntu config --default-user $username"
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
		# TODO:
		# https://github.com/ElvisDot/lewagon-setup/issues/24
		# will fail with the following brew warning
		#
		# Warning: Running in non-interactive mode because `stdin` is not a TTY.
		# Need sudo access on macOS (e.g. the user $USER needs to be an Administrator)!
		#
		# then the doctor will fail in the next step
		# can we either invoke this with sudo or force the doctor to be interactive?
		# otherwise this does not make sense
		if ! /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
		then
			error "Error: failed to install brew."
			error "       Please run the following command and check the errors"
			error ""
			error "       ${_color_WHITE}/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
			error ""
			exit 1
		fi

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
	[ "$detected_os" = "macOS" ] && return 0
	return 1
}
function is_arm() {
	[[ "$mac_arch" =~ arm ]] && return 0
	return 1
}
function is_linux() {
	[ "$detected_os" = "Linux" ] && return 0
	return 1
}
function is_ubuntu() {
	[[ "$detected_distro" =~ [Uu]buntu ]] && return 0
	return 1
}
function is_windows() {
	[ "$detected_os" = "WSL" ] && return 0
	return 1
}

function device_info() {
	# os
	if [[ $OSTYPE = 'darwin'* ]]
	then
		detected_os='macOS'
	elif grep -q Microsoft /proc/version || uname -a | grep -iq '^Linux.*Microsoft'
	then
		detected_os='WSL'
	elif [ "$(uname)" = "Linux" ]
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
		if winver="$(pwsh "[System.Environment]::OSVersion.Version.Major" | tr -d '\r')"
		then
			# note that winver is 10 on windows 11 but it is less than 10 on windows 8
			if [ "$winver" -lt "10" ]
			then
				warn "Warning: your windows is outdated please do a update"
			fi
		else
			warn "Warning: failed to get windows version"
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
		if [ "$is_running_default" = "" ]
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
	if is_doc_deprecated
	then
		warn "Warning: this script has not been updated in a long time"
		warn "         it might be outdated"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
	fi
}

function check_shell() {
	if [[ "$SHELL" =~ zsh ]]
	then
		return
	fi

	local default_shell
	if [ -x "$(command -v getent)" ]
	then
		if [[ "$(getent passwd "$USER" | awk -F: '{print $NF}')" = "$(command -v zsh)" ]]
		then
			# it might not have been applied yet
			# or the user manually launched a zsh session
			# but the correct shell is set in the profile
			# so do not alert
			return
		fi
	elif [ -x "$(command -v dscl)" ] && is_mac
	then
		# dscl . -read ~/ UserShell
		# UserShell: /bin/zsh
		if ! default_shell="$(dscl . -read ~/ UserShell | cut -d' ' -f2-)"
		then
			warn "Warning: failed to get default shell via dscl"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		if [ "$default_shell" = "$(command -v zsh)" ]
		then
			return
		fi
	elif ! is_mac
	then
		if ! default_shell="$(grep "^$USER:" /etc/passwd | cut -d':' -f7)"
		then
			warn "Warning: failed to detect default shell from /etc/passwd"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		if [ "$default_shell" = "" ]
		then
			warn "Warning: failed to detect default shell from /etc/passwd"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		if [ "$default_shell" == "$(command -v zsh)" ]
		then
			return
		fi
	else
		warn "Warning: failed to detect default shell on your system"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi

	if [ "$arg_fix" = "0" ]
	then
		warn "Warning: zsh is not your default shell"
		warn "         you can set your default shell by running this command:"
		warn ""
		warn "           ${_color_WHITE}chsh -s \"\$(command -v zsh)\""
		warn ""
		warn "         or run the doctor with $_color_WHITE--fix"
		warn ""
	else
		if [ -x "$(command -v zsh)" ]
		then
			log "Setting default shell to ${_color_GREEN}zsh"
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
	if [ "$arg_fix" = "1" ]
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
		elif [ -L /etc/resolv.conf ]
		then
			wrn "Warning: /etc/resolv.conf is an invalid symlink"
			log "Cleaning up /etc/resolv.conf ..."
			sudo rm -f /etc/resolv.conf
		fi
		if [ -f /etc/wsl.conf ]
		then
			local backup_conf
			if ! backup_conf="$(mktemp /tmp/lewagon-doc/XXXXXX_wsl.conf.backup)"
			then
				error "Error: failed to create temp backup file"
				exit 1
			fi
			cat /etc/wsl.conf > "$backup_conf"
			log "Updating $_color_WHITE/etc/wsl.conf$_color_RESET to fix dns."
			log "The old wsl.conf is backed up at $_color_green$backup_conf$_color_RESET"
		fi
		sudo bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
		sudo bash -c 'echo "[network]" > /etc/wsl.conf'
		sudo bash -c 'echo "generateResolvConf = false" >> /etc/wsl.conf'
		if ! sudo chattr +i /etc/resolv.conf
		then
			warn "Warning: the chattr command failed falling back to boot command"
			sudo bash -c 'echo "[boot]" >> /etc/wsl.conf'
			sudo bash -c 'echo "command=\"echo '"'"'nameserver 8.8.8.8'"'"' > /etc/resolv.conf"\" >> /etc/wsl.conf'
		fi
		return
	fi
	error "Error: your dns is not working. Try running these commands"
	error ""
	error "       ${_color_WHITE}sudo rm /etc/resolv.conf"
	error "       ${_color_WHITE}sudo bash -c 'echo \"nameserver 8.8.8.8\" > /etc/resolv.conf'"
	error "       ${_color_WHITE}sudo bash -c 'echo \"[network]\" > /etc/wsl.conf'"
	error "       ${_color_WHITE}sudo bash -c 'echo \"generateResolvConf = false\" >> /etc/wsl.conf'"
	error "       ${_color_WHITE}sudo chattr +i /etc/resolv.conf"
	error ""
	error "       or run the doctor with $_color_WHITE--fix"
	error ""
}

function check_ipv6_ok() {
	dbg -n "checking ipv6 ... "

	local ips=(2001:4860:4860::8888 2606:4700:4700::1111)
	for ip in "${ips[@]}"
	do
		if ping "$ip" -6 -c 1 -W 2 &>/dev/null
		then
			g_ipv6_ok=1
			dbg_echo "${_color_GREEN}OK"
			return
		fi
	done

	# Some networks including github CI might block ping
	# So do a http fallback test before concluding the internet is down
	local host
	local hosts=(http://github.com http://lewagon.com http://google.com)
	for host in "${hosts[@]}"
	do
		if check_http "$host" --ipv6
		then
			g_ipv6_ok=1
			dbg_echo "${_color_GREEN}OK"
			return
		fi
	done
	if [ "$g_ipv6_ok" = "0" ]
	then
		dbg_echo "${_color_RED}NOT WORKING"
	fi
}

function check_basics() {
	dbg "checking internet connectivity ..."
	check_ipv6_ok
	if ! check_dns
	then
		fail_if_no_internet

		if is_windows
		then
			fix_dns_wsl
		fi
	fi
	if [ "$arg_full" = "1" ]
	then
		check_ssl
	fi
	check_shell
	if is_windows || is_linux
	then
		check_user_windows
	fi
}

function check_vscode_location() {
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
	if is_windows
	then
		if ! echo "$PATH" | grep -q "/mnt/c/.*/username/AppData/Local/Programs/Microsoft VS Code/bin"
		then
			local path_overwrites
			# shellcheck disable=SC2016
			path_overwrites="$(grep -n PATH= ~/.zshrc ~/.zprofile | grep -Ev '(\$PATH|\${PATH})')"
			warn "Warning: vscode does not seem to be in your PATH"
			warn "         this might be caused by someone overwriting PATH"
			warn "         check the files ~/.zprofile and ~/.zshrc"
			if [ "$path_overwrites" != "" ]
			then
				warn "         The doctor found these lines that may cause issues:"
				local path_overwrite
				for path_overwrite in $path_overwrites
				do
					warn "           $_color_red$path_overwrite"
				done
			fi
			warn ""
			warn "         Alternativley you can try reinstalling vscode on your windows system"
		fi
	fi
}

function check_vscode() {
	dbg "checking vscode ..."
	is_vscode_healthy=0
	if [ -x "$(command -v code)" ]
	then
		return
	fi
	check_vscode_location
	if is_windows
	then
		if [ ! -d ~/.vscode-server ]
		then
			warn "Warning: did not find ~/.vscode-server"
			warn "         if you did not install vscode yet"
			warn "         or your ${_color_WHITE}code$_color_yellow command works fine"
			warn "         you can ignore this warning"
		fi
	fi
	local vscode_version
	if ! vscode_version="$(code --version)"
	then
		warn "Warning: failed to get vscode version"
		if is_windows
		then
			warn "         you can try reinstalling and or deleting your vscode-server"
			warn "         directory by running the following command:"
			warn ""
			warn "  ${_color_WHITE}rm -rf ~/.vscode-server"
			warn ""
		fi
		return
	fi
	if [ "$vscode_version" = "" ]
	then
		warn "Warning: ${_color_WHITE}code --version$_color_yellow output is empty"
		return
	fi
	is_vscode_healthy=1
}

# the doctor would not work at all if the PATH
# is that broken
function check_path_overwritten() {
	if echo "$PATH" | grep -q '/bin'
	then
		return
	fi
	local path_overwrites
	# shellcheck disable=SC2016
	path_overwrites="$(grep -n PATH= ~/.zshrc ~/.zprofile | grep -Ev '(\$PATH|\${PATH})')"
	warn "Warning: your PATH does not look healthy"
	if [ "$path_overwrites" != "" ]
	then
		warn "         The doctor found these lines that may cause issues:"
		local path_overwrite
		for path_overwrite in $path_overwrites
		do
			warn "           $_color_red$path_overwrite"
		done
	fi
}

function is_data() {
	[ "$bootcamp" = "data" ] && return 0
	return 1
}
function is_web() {
	[ "$bootcamp" = "web" ] && return 0
	return 1
}

function list_vscode_extensions() {
	# returns cached extensions.json
	# and falls back to the more buggy
	# code --list--extensions if the json is not found
	if [ "$g_vscode_extensions_cache" != "" ]
	then
		echo "$g_vscode_extensions_cache"
		return
	fi
	local extension_dir="$HOME/.vscode/extensions"
	is_windows && extension_dir="$HOME/.vscode-server/extensions"

	local ext_json="$extension_dir/extensions.json"
	if [ -f "$ext_json" ]
	then
		if ! g_vscode_extensions_cache="$(cat "$ext_json")"
		then
			g_vscode_extensions_cache=''
		fi
	elif [ -x "$(command -v code)" ]
	then
		# this command is not stable and fails on healthy systems
		# it should be a last resort for listing extensions
		if ! g_vscode_extensions_cache="$(code --list-extensions)"
		then
			g_vscode_extensions_cache=''
		fi
	fi
	echo "$g_vscode_extensions_cache"
}

function check_vscode_extensions_web() {
	dbg "checking vscode extensions (web bootcamp) ..."

	[ -x "$(command -v code)" ] || return

	local vscode_extensions="$WANTED_VSCODE_EXTENSIONS_WEB"
	is_windows && vscode_extensions="$vscode_extensions ms-vscode-remote.remote-wsl"

	local num_extensions
	if ! num_extensions="$(printf '%s' "$vscode_extensions" | grep -o . | grep -c ' ')"
	then
		error "Error: failed to get number of vscode extensions"
		error "       this is likley an issue with the doctor it self"
		error "       please report it here"
		error ""
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		error ""
		exit 1
	fi

	local i=0
	local ext
	while [ "$i" -le "$num_extensions" ]
	do
		i="$((i+1))"
		ext="$(printf '%s' "$vscode_extensions" | cut -d' ' -f"$i")"
		[ "$ext" = "" ] && continue

		# not sure if extensions are case sensitive
		# just in case they are not lets not warn if there
		# is another casing installed than expected
		list_vscode_extensions | grep -iqF "$ext" && continue

		warn "Warning: missing vscode extension: ${_color_YELLOW}$ext"
		warn "         run the following command to install it"
		warn ""
		warn "  ${_color_WHITE}code --install-extension $ext"
		warn ""
	done
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
	if [ -f ~/.zshrc ] && grep -q direnv ~/.zshrc
	then
		bootcamp=data
	fi
	if [ -x "$(command -v code)" ] && [ "$is_vscode_healthy" = "1" ]
	then
		if list_vscode_extensions | grep -q ruby
		then
			bootcamp=web
		fi
		if list_vscode_extensions | grep -Eqi '(jupyter|pylance)'
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
	if cd_into_fullstack_challenges
	then
		bootcamp=web
	fi
	log "Assuming $_color_YELLOW$bootcamp$_color_RESET bootcamp"
}

# cached github username lookup
# based on gh cli authentication
# (may differ for github ssh see 'get_gh_ssh_username')
#
# if github_username="$(get_gh_cli_username)"
# then
# 	log "logged in as $github_username"
# fi
function get_gh_cli_username() {
	[ -x "$(command -v gh)" ] || return 1
	[ -x "$(command -v jq)" ] || return 1

	if [ "$g_github_cli_username" = null ]
	then
		return 1
	fi
	if [ "$g_github_cli_username" != "" ]
	then
		printf '%s' "$g_github_cli_username"
		return 0
	fi
	if ! g_github_cli_username="$(gh api user | jq -r .login)"
	then
		g_github_cli_username=null
		return 1
	fi
	if [ "$g_github_cli_username" = "" ]
	then
		g_github_cli_username=null
		return 1
	fi
	printf '%s' "$g_github_cli_username"
	return 0
}

# cached github username lookup
# based on ssh authentication
# (may differ for gh cli see 'get_gh_cli_username')
#
# if github_username="$(get_gh_ssh_username)"
# then
# 	log "logged in as $github_username"
# fi
function get_gh_ssh_username() {
	if [ "$g_github_ssh_username" = null ]
	then
		return 1
	fi
	if [ "$g_github_ssh_username" != "" ]
	then
		echo "$g_github_ssh_username"
		return 0
	fi
	local ssh_t_github
	ssh_t_github="$(ssh -T git@github.com 2>&1)"
	if [ "$?" != "1" ]
	then
		warn "Warning: failed to get github username" 1>&2
		warn "         $_color_red$ssh_t_github" 1>&2
		g_github_ssh_username=null
		return 1
	fi
	g_github_ssh_username="$(echo "$ssh_t_github" | cut -d' ' -f2 | cut -d'!' -f1)"
	# the regex is the nicer solution but the capture group causes a
	# syntax issue on bash 3
	# if [[ "$(ssh -T git@github.com 2>&1)" =~ Hi\ (.*)! ]]
	# then
	# 	g_github_ssh_username="${BASH_REMATCH[1]}"
	# fi
	if [ "$g_github_ssh_username" = "" ]
	then
		# this is a bit dirty to not check the gh name again
		# if it failed once
		# we assume here that the github user https://github.com/null
		# does not run this script
		g_github_ssh_username=null
		return 1
	fi
	echo "$g_github_ssh_username"
	return 0
}

# cached auth status
# prints empty string and returns 1 if not authed
# prints the output of "gh auth status" otherwise
#
# if ! gh_auth_status > /dev/null
# then
# 	error "Error: not logged in"
# fi
function gh_auth_status() {
	if [ "$g_gh_auth_status" = "false" ]
	then
		return 1
	fi
	if [ "$g_gh_auth_status" != "" ]
	then
		echo "$g_gh_auth_status"
		return 0
	fi
	if ! g_gh_auth_status="$(gh auth status 2>&1)"
	then
		g_gh_auth_status=false
		return 1
	fi
	echo "$g_gh_auth_status"
	return 0
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
		if [ "$arg_fix" = "1" ]
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
			warn ""
		fi
	fi

	if [ "$arg_fix" = "0" ]
	then
		warn "Warning: please install rbenv or run the doctor with $_color_WHITE--fix"
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

# @param version1
# @param version2
# @param comment used for error messages
#
# @returns true if version1 >= version2
#
# @example
#
# if semver_ge "1.2.3" "2.0.0" foo
# then
# 	# unreachable code
# 	echo "1.2.3 is greater than 2.0.0"
# fi
#
# if semver_ge "2.2.3" "2.0.0" foo
# then
# 	# reachable code
# 	echo "2.2.3 is greater than 2.0.0"
# fi
function semver_ge() {
	local version1="$1"
	local version2="$2"
	local comment="$3"

	local v
	for v in "$version1" "$version2"
	do
		if ! echo "$v" | grep -qE '^([0-9]+)\.([0-9+])\.([0-9]+)'
		then
			warn "Warning: failed to compare $comment version. '$_color_RED$v$_color_YELLOW' is not a valid version number."
			warn "         this is an issue with the doctor please report it here"
			warn ""
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return 1
		fi
	done

	# macOS:
	# Usage: sort [-bcCdfigMmnrsuz] [-kPOS1[,POS2] ... ] [+POS1 [-POS2]] [-S memsize] [-T tmpdir] [-t separator] [-o outfile] [--batch-size size] [--files0-from file] [--heapsort] [--mergesort] [--radixsort] [--qsort] [--mmap] [--parallel thread_no] [--human-numeric-sort] [--version-sort] [--random-sort [--random-source file]] [--compress-program program] [file ...]

	if ! sort --help | grep -qE -- "([[:space:]]-V[^a-z]|--version-sort)"
	then
		warn "Warning: failed to check $comment version (sort -V not supported)"
		warn "         this is an issue with the doctor please report it here"
		warn ""
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return 1
	fi

	local latest
	# get latest version of the list "current" and "wanted"
	# sort -V supports semantic versioning sort
	# using tail -n1 we get the latest
	latest="$(printf '%s\n%s\n' "$version2" "$version1" | sort -V | tail -n1)"

	[[ "$version1" != "$latest" ]] && return 1
	return 0
}

function is_outdated_ruby() {
	local ruby_vers
	ruby_vers="$(ruby -e "puts RUBY_VERSION" 2>/dev/null)"

	# does not work in bash 3
	# if ! [[ "$ruby_vers" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]
	if ! echo "$ruby_vers" | grep -qE '^([0-9]+)\.([0-9+])\.([0-9]+)'
	then
		warn "Warning: failed to parse ruby version '$ruby_vers'"
		# if we do not detect semver we count it as outdated
		# should technically even support but who knows truffleruby, mruby or jruby
		# some custom ruby version *might* fail in that case we claim its outdated
		return 1
	fi

	# if we are the wanted version we are good
	# but also if we are more recent than the wanted version we are good
	semver_ge "$ruby_version" "$(wanted_ruby_version)" ruby && return 0
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
	if [ "$(command -v brew)" = "/usr/local/bin/brew" ]
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
		if [ "$arg_fix" = "1" ]
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
	if [ "$set_version" != "" ] && [ "$set_version" = "$(wanted_ruby_version)" ]
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
	if [ "$got_wanted" = "$(wanted_ruby_version)" ]
	then
		if [ "$arg_fix" = "1" ]
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
	dbg "checking ruby ..."
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
		if [ "$rbenv_vers" != "system" ] && [ "$rbenv_vers" = "" ]
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
		if [ "$arg_fix" = "1" ]
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
	local dotfiles_needed=1
	if [ "$1" = "--no-dotfiles-needed" ]
	then
		dotfiles_needed=0
	fi
	for dir in ~/code/*/
	do
		local dirname
		dirname="$(basename "$dir")"
		[ -d "$dir" ] || return 1
		[[ "$dirname" =~ ^[Ll]e[Ww]agon$ ]] && continue
		[[ "$dirname" =~ ^workshops?$ ]] && continue
		[[ "$dirname" =~ ^students?$ ]] && continue
		[[ "$dirname" =~ ^lectures?$ ]] && continue
		[ "$dirname" = livecode ] && continue
		[ "$dirname" = tmp ] && continue
		[ "$dirname" = reboot ] && continue
		if [ "$dotfiles_needed" = "1" ]
		then
			[ ! -d "$dir"/dotfiles ] && continue
		fi

		dotfiles_dir="$dir"
	done
	if [ "${BASH_VERSINFO:-0}" -lt 4 ]
	then
		echo "$dotfiles_dir"
	else
		# get rid of trailing slash
		[ "$dotfiles_dir" != "" ] && echo "${dotfiles_dir::-1}"
	fi
}

function run_dotfiles_install() {
	local dir
	local dotfiles_dir=''
	dotfiles_dir="$(get_code_user_dir)"
	if [ ! -d "$dotfiles_dir" ] || [ "$dotfiles_dir" = "" ]
	then
		dotfiles_dir="$(get_code_user_dir --no-dotfiles-needed)"
		local github_username
		if github_username="$(get_gh_ssh_username)"
		then
			dotfiles_dir="$HOME/code/$github_username"
			if [ ! -d "$dotfiles_dir" ]
			then
				log "Creating folder $_color_green$dotfiles_dir"
				if ! mkdir -p "$dotfiles_dir"
				then
					error "Error: failed to create $dotfiles_dir"
					exit 1
				fi
			fi
		fi
		local found_wrong_dotfiles=''
		if [ -d "$HOME/code/dotfiles" ]
		then
			found_wrong_dotfiles="$HOME/code/dotfiles"
		elif [ -d "$HOME/dotfiles" ]
		then
			found_wrong_dotfiles="$HOME/dotfiles"
		fi
		if [ -d "$dotfiles_dir" ] && [ "$dotfiles_dir" != "" ] && [ "$found_wrong_dotfiles" != "" ]
		then
			if [ "$arg_fix" = "1" ]
			then
				if ! mv "$found_wrong_dotfiles" "$dotfiles_dir/dotfiles"
				then
					error "Error: failed to move ~/code/dotfiles to $found_wrong_dotfiles"
					exit 1
				fi
				dotfiles_dir="$(get_code_user_dir)"
				if [ ! -d "$dotfiles_dir" ] || [ "$dotfiles_dir" = "" ]
				then
					error "Error: did not find dotfiles directory"
					exit 1
				fi
			else
				error "Error: did not find dotfiles folder in expected location"
				error "       but did find it in your code folder"
				error "       you probably want to move that into the correct location"
				error ""
				error "       found:    ${_color_RED}$found_wrong_dotfiles"
				error "       expected: ${_color_green}$dotfiles_dir/dotfiles"
				error ""
				error "       try moving it using the following command:"
				error ""
				error "  ${_color_WHITE}mv ~/code/dotfiles $dotfiles_dir/dotfiles"
				error ""
				error "       or run the doctor with $_color_WHITE--fix"
				exit 1
			fi
		else
			error "Error: you are missing the dotfiles folder"
			error "       follow those steps again"
			error ""
			local os_url='macOS'
			is_windows && os_url='windows'
			if is_data
			then
				error "       https://github.com/lewagon/data-setup/blob/master/$os_url.md#dotfiles"
			else
				error "       https://github.com/lewagon/setup/blob/master/$os_url.md#dotfiles-standard-configuration"
			fi
			error ""
			exit 1
		fi
	fi
	cd "$dotfiles_dir"/dotfiles || { error "Error: something went wrong"; exit 1; }
	local is_pass_note=0

	if grep "password is 123" ~/.zshrc
	then
		is_pass_note=1
	fi

	if [ "$is_dotfiles_old" = "1" ]
	then
		warn "Warning: skipping dotfiles setup because your dotfiles are outdated"
		warn "         please run this manually"
		warn ""
		warn "           ${_color_WHITE}cd $PWD"
		warn "           ${_color_WHITE}zsh install.sh"
		warn ""
		return
	fi

	if [ ! -f install.sh ] || [ "$(awk NF install.sh | wc -l)" = "0" ]
	then
		log "The $_color_yellow$PWD/install.sh$_color_RESET is empty or missing. Trying git restore."
		git checkout install.sh
	fi
	if [ ! -f install.sh ]
	then
		error "Error: missing install.sh script in dotfiles folder"
		error "       expected the following file to exist:"
		error "       ${_color_YELLOW}$PWD/install.sh"
		exit 1
	fi
	if [ "$(awk NF install.sh | wc -l)" = "0" ]
	then
		error "Error: empty install.sh script in dotfiles folder"
		error "       expected the following file to have contents:"
		error "       ${_color_YELLOW}$PWD/install.sh"
		exit 1
	fi
	assert_num_file_lines "$PWD/install.sh" 20 150
	local install_sh_firstline
	if ! install_sh_firstline="$(head -n1 install.sh)"
	then
		error "Error: failed to get install.sh contents"
		error "       ${_color_WHITE}head -n1 $PWD/install.sh"
		exit 1
	fi
	if [ "$install_sh_firstline" != '#!/bin/zsh' ]
	then
		warn "Warning: ${_color_WHITE}$PWD/install.sh$_color_yellow does not start with a zsh shebang"
		warn "         expected: ${_color_green}#!/bin/zsh"
		warn "              got: ${_color_red}$install_sh_firstline"
		if [ "$install_sh_firstline" = "" ]
		then
			local non_empty_line
			if ! non_empty_line="$(grep -vnH '^[[:space:]]*$' install.sh | head -n1)"
			then
				warn "Warning: failed to get first non empty line of install.sh"
			else
				warn "         first non empty line: ${_color_WHITE}$non_empty_line"
			fi
		fi
	fi

	log "running ${_color_green}cd $PWD && zsh install.sh"
	zsh install.sh

	if [ "$is_pass_note" = "1" ]
	then
		if ! grep "password is 123" ~/.zshrc
		then
			password_note >> ~/.zshrc
		fi
	fi
}

function check_dotfiles() {
	dbg "checking dotfiles ..."
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
		[ ! -f "$dotfile" ] && broken_links=1

		# non symlink dotfiles
		if [ ! -L "$dotfile" ]
		then
			warn "Warning: found dotfile that is not a symlink ${_color_red}$dotfile"
			broken_links=1
			continue
		fi

		# if the symlink is dead
		# (pointing to a invalid file)
		# delete it so the lewagon setup can relink it
		if [ ! -e "$dotfile" ]
		then
			log "cleaning up dead symlink ${_color_YELLOW}$dotfile"
			rm "$dotfile"
			broken_links=1
		fi
	done
	if [ "$broken_links" = "1" ]
	then
		run_dotfiles_install
	fi
	local found_dotfiles=0
	if [ "$(get_code_user_dir)" != "" ]
	then
		found_dotfiles=1
	fi
	if [ ! -f ~/.zshrc ]
	then
		warn "Warning: missing file ~/.zshrc"
		found_dotfiles=0
	fi
	if [ ! -f ~/.zprofile ] && is_data
	then
		# pyenv stuff is only crucial for data students
		error "Error: missing zprofile in dotfiles"
		found_dotfiles=0
	fi
	if [ "$found_dotfiles" = "1" ]
	then
		if ! grep -q "rbenv init" ~/.zshrc
		then
			warn "Warning: did not find 'rbenv init' in ~/.zshrc"
		fi
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
	if is_windows
	then
		warn "         install docker desktop on your windows host"
		warn "         following these instructions https://docs.docker.com/desktop/wsl/"
	elif is_mac
	then
		warn "         get it from here https://docs.docker.com/desktop/install/mac-install/"
	else
		warn "         get it from here https://docs.docker.com/get-docker/"
	fi
	warn ""
}

function check_docker_running() {
	# TODO: service docker start
	test
}

function check_docker() {
	dbg "checking docker ..."
	check_docker_installed
	check_docker_running
}

function check_github_access() {
	dbg "checking github access ..."
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
	local git_protocol
	if ! git_protocol="$(gh config get git_protocol --host github.com)"
	then
		warn "Warning: failed to detect github cli protocol"
	else
		if [ "$git_protocol" = "https" ]
		then
			log "Changing github cli git protocol from ${_color_yellow}https${_color_RESET} to ${_color_green}ssh"
			gh config set git_protocol ssh --host github.com
		elif [ "$git_protocol" != "ssh" ]
		then
			warn "Warning: got unexpected github cli git protocol '$git_protocol'"
		fi
	fi
	if [ "$GITHUB_CI" != "" ]
	then
		warn "Warning: ignoring gh auth because GITHUB_CI is set"
		return
	fi
	local is_logged_in=1
	if [ "$arg_full" = "1" ]
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

	if [ "$is_logged_in" = "1" ]
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
		[[ "$ssh_pub" = "id_ed25519.pub" ]] && continue

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

function check_gh_cli() {
	if is_mac
	then
		if [ ! -x "$(command -v gh)" ]
		then
			brew install gh
		fi
		return
	fi
	if gh --version 2>&1 | grep -q 'github.com/cli/cli/releases'
	then
		return
	fi

	if [ ! -x "$(command -v curl)" ]
	then
		sudo apt-get install -y curl
	fi
	# gh command can conflict with gitsome if already installed
	if [ -x "$(command -v gh)" ]
	then
		log "Found gitsome! Uninstalling and installing gh cli instead"
		sudo apt-get remove -y gitsome
	fi
	curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
	echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" |
		sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
	sudo apt-get update -y
	sudo apt-get install -y gh
}

function check_package_manager_programs() {
	dbg "checking installed programs ..."
	local programs=()
	local prog
	if is_mac && is_data
	then
		for prog in ncdu xz
		do
			[[ -x "$(command -v "$prog")" ]] || programs+=("$prog")
		done
		if ! brew list readline | grep readline &>/dev/null
		then
			programs+=("readline")
		fi
	else # linux/windows
		for prog in unzip vim zsh
		do
			[[ -x "$(command -v "$prog")" ]] || programs+=("$prog")
		done
	fi

	for prog in git jq gh wget openssl
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
			if [ "$arg_fix" = "1" ]
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
	local postgres_status_matches
	if ! postgres_status_matches="$(brew services | grep postgres)"
	then
		warn "Warning: failed to get postgres status"
		return
	fi
	if [ "$postgres_status_matches" = "" ]
	then
		warn "Warning: no postgres service installed"
		warn "         is postgres installed with brew?"
		warn ""
		warn "         this is probably a bug of the doctor it self"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	local postgres_status_column
	postgres_status_column="$(echo "$postgres_status_matches" | awk '{ print $2 }')"
	if ! echo "$postgres_status_column" | grep -q started
	then
		if [ "$(echo "$postgres_status_matches" | xargs)" = "postgresql@$WANTED_POSTGRES_VERSION none" ]
		then
			# there is only one postgres version installed
			# it is the correct one
			# it is not running
			# and it is not in error state
			# -> just start it duh
			log "starting postgres service ..."
			if ! brew services start postgresql@"$WANTED_POSTGRES_VERSION"
			then
				warn "Warning: failed to start postgres"
				warn "         running the command below failed with the error above"
				warn ""
				warn "           ${_color_WHITE}brew services start postgresql@$WANTED_POSTGRES_VERSION"
			else
				log -n "waiting for postgres to get healthy"
				local i
				for((i=0;i<3;i++))
				do
					printf '.'
					sleep 1
				done
				printf '\n'
			fi
			return
		fi
		warn "Warning: postgres is not running"
		warn ""
		warn "         $_color_WHITE$postgres_status_matches"
		warn ""
		# check if a non brew postgres is blocking the port
		local blocked_port
		local lsof_ip
		if ! lsof_ip="$(lsof -i -P)"
		then
			warn "Warning: failed to check for blocked port"
			warn "         try running this and check for errors"
			warn ""
			warn "         ${_color_WHITE}lsof -i -P"
			warn ""
			warn "         this is a bug of the doctor it self"
			warn "         please report this issue here"
			warn "         https://github.com/ElvisDot/lewagon-setup/issues"
			return
		fi
		if ! echo "$lsof_ip" | grep ":5432 (LISTEN)"
		then
			# port not blocked by someone else
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
	if [ -f /etc/init.d/postgresql ]
	then
		if ! /etc/init.d/postgresql status &>/dev/null
		then
			if [ "$arg_fix" = "1" ]
			then
				log "starting postgresql service ..."
				sudo /etc/init.d/postgresql start
			else
				warn "Warning: postgresql service is not running"
				warn "         try starting postgres using this command"
				warn ""
				warn "         ${_color_WHITE}sudo /etc/init.d/postgresql start"
				warn ""
				warn "         to fix it automatically"
				warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
			fi
		fi
		return
	fi
	if ! pidof -q systemd
	then
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
		if [ "$arg_fix" = "1" ]
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
		return 0
	fi
	if is_windows || is_linux
	then
		if ! sudo -u postgres psql -d postgres -c '\l' > /dev/null
		then
			warn "Warning: failed to list postgres databases"
			warn "         try running this command and check if there are any errors"
			warn ""
			warn "         ${_color_WHITE}sudo -u postgres psql -d postgres -c '\\l' > /dev/null"
			warn ""
			return 1
		fi
	fi
	return 1
}

function check_postgres_role() {
	if psql -lqt -U "$(whoami)" &> /dev/null
	then
		# we cann login and list databases using our user
		# assume everything is OK
		# to avoid prompting for sudo password on healthy systems
		return 0
	fi
	if [ "$USER" = "root" ]
	then
		warn "Warning: can not check postgres role when running as root"
		return 1
	fi
	local username
	if ! username="$(id -u -n)"
	then
		warn "Warning: failed to check postgres role"
		return 1
	fi
	if [ "$USER" != "$username" ] || [ "$USER" = "" ]
	then
		warn "Warning: failed to check postgres role USER='$USER' username='$username'"
		return 1
	fi
	if [[ ! "$USER" =~ ^[a-z][-a-z0-9_]*$ ]]
	then
		warn "Warning: failed to check postgres role USER='$USER' (invalid name)"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return 1
	fi
	local postgres_roles
	if is_windows || is_mac
	then
		if ! postgres_roles="$(sudo -u postgres psql -d postgres -c "SELECT * FROM pg_roles WHERE rolname = '$USER';" 2>/dev/null)"
		then
			warn "Warning: failed to get postgres role"
			warn "         try running this and look at the errors"
			warn ""
			warn "           ${_color_WHITE}sudo -u postgres psql -d postgres -c \"SELECT * FROM pg_roles WHERE rolname = '$USER';\""
			warn ""
			return
		fi
		if ! echo "$postgres_roles" | grep -q '1 row'
		then
			warn "Warning: missing postgresql role"
			warn "         try running this command"
			warn ""
			warn "         ${_color_WHITE}sudo -u postgres psql --command 'CREATE ROLE \"$(whoami)\" LOGIN createdb superuser;'"
			warn ""
		fi
	elif is_mac
	then
		# TODO: find a linux equivalent cheat on macOS to check roles
		#       we need to somehow abuse sudo or anything else to check if our role exists
		#       but we can not access the database since we assume our role does not exist
		warn "Warning: your role might be missing but the doctor is not sure"
		warn "         is anyone else using this device?"
	fi
	return 1
}

function check_postgres_create_db() {
	if psql -U "$(whoami)" -lqt | grep -q lewagon_doc_test_db_delete_me
	then
		# TODO: should we warn here?
		# 	this means either the student created a db with this name
		# 	or the script failed to delete it
		# 	either way its a edge case and the system is probably healthy
		return 0
	fi
	if ! psql -U "$(whoami)" -d postgres -c 'CREATE DATABASE lewagon_doc_test_db_delete_me;' > /dev/null
	then
		warn "Warning: failed to create postgres database"
		return 1
	fi
	if ! psql -U "$(whoami)" -d postgres -c 'DROP DATABASE lewagon_doc_test_db_delete_me;' > /dev/null
	then
		warn "Warning: failed to delete postgres database"
		return 1
	fi
	return 0
}

function show_postgres_logs_macos() {
	local log
	for log in \
		/opt/Homebrew/var/log/postgresql@"$WANTED_POSTGRES_VERSION".log \
		/usr/local/var/log/postgresql@"$WANTED_POSTGRES_VERSION".log
	do
		[ -f "$log" ] || continue

		log "Got postgres logfile at ${_color_GREEN}$log"
		log "head:"
		head "$log"
		log "tail:"
		tail "$log"
	done
}

function show_postgres_storage_macos() {
	local dir
	for dir in /usr/local/var/postgres*/ /opt/homebrew/var/postgres*/
	do
		[ -d "$dir" ] || continue

		log "Found postgres folder: ${_color_GREEN}$dir"
	done
}

function show_postgres_configs_macos() {
	local dir
	for dir in /usr/local/var/postgres*/ /opt/homebrew/var/postgres*/
	do
		[ -d "$dir" ] || continue

		local conf_file="$dir"postgresql.conf
		[ -f "$conf_file" ] || continue

		log "Found postgres config: $conf_file"
		log "  Number of lines: $(wc -l "$conf_file")"
		if [ "$arg_verbose" -gt 1 ]
		then
			local max_print_lines=20
			log "  First $max_print_lines lines:"
			awk NF "$conf_file" | grep -vE '^[[:space:]]*#' | head -n"$max_print_lines"
		fi
	done
}

function show_postgres_pids_macos() {
	local dir
	for dir in /usr/local/var/postgres*/ /opt/homebrew/var/postgres*/
	do
		[ -d "$dir" ] || continue

		local pid_file
		for pid_file in "$dir"*.pid
		do
			[ -f "$pid_file" ] || continue

			# TODO: https://github.com/ElvisDot/lewagon-setup/issues/2
			#	if it is save to delete that pid file that should be attempted
			#	or suggested here
			log "Found postgres pid:"
			ls -lah "$pid_file"
		done
	done
}

function check_database() {
	dbg "checking database ..."
	# TODO: persist postgres start command on wsl in zshrc
	check_postgres_and_sqlite_installed
	if is_mac
	then
		check_postgres_running_mac
	else
		check_postgres_running_linux
	fi
	local posgres_unhealthy=0
	if ! check_postgres_health || ! check_postgres_role || ! check_postgres_create_db
	then
		warn "Warning: your postgres is not healthy."
		warn "         check the above warnings for more details."
		warn "         or look at the errors of this command:"
		warn ""
		warn "           ${_color_WHITE}psql -lqt -U \"$(whoami)"\"
		warn ""
		posgres_unhealthy=1
	fi
	if [ "$arg_verbose" -gt 1 ] || [ "$posgres_unhealthy" = 1 ]
	then
		if is_mac
		then
			show_postgres_logs_macos
			show_postgres_storage_macos
			show_postgres_configs_macos
			show_postgres_pids_macos
		fi
	fi
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
	if [ "$(csrutil status)" = "System Integrity Protection status: enabled." ]
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

	local github_ssh_username
	if ! github_ssh_username="$(get_gh_ssh_username)"
	then
		return 1
	fi
	dbg "Found github ssh name $_color_green$github_ssh_username"

	local github_cli_username
	if github_cli_username="$(get_gh_cli_username)"
	then
		dbg "Found github cli name $_color_green$github_cli_username"
		if [ "$github_cli_username" != "$github_ssh_username" ]
		then
			warn "Warning: there are two github usernames found"
			warn "         one authed via ssh: $_color_RED$github_ssh_username"
			warn "         one authed via cli: $_color_RED$github_cli_username"
		fi
	fi

	local code_dir_username
	code_dir_username="$(basename "$(get_code_user_dir)")"
	if [ "$code_dir_username" = "" ]
	then
		return 1
	fi
	if [ "$github_ssh_username" != "$code_dir_username" ]
	then
		warn "Warning: there are two usernames found"
		warn "         one in your ~/code dir: $_color_RED$code_dir_username"
		warn "         one  authed on  github: $_color_RED$github_ssh_username"
		return 0
	fi
	return 1
}

function check_ready_commit_email() {
	dbg "check ready commit email ..."

	# Kitt is waiting for the student
	# to push a commit with the correct email
	# set in the fullstack-challenges repo
	if ! gh_auth_status > /dev/null
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
	if ! github_email="$(gh_email_primary)"
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
	if [ "$ready_email" = "$github_email" ]
	then
		return
	fi
	warn 'Warning: your github email is not in the "I am so ready" commit'
	warn "         ready  email: $_color_RED$ready_email"
	warn "         github email: $_color_RED$github_email"
	if [ "$arg_fix" = "1" ]
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
	if ! gh_auth_status &> /dev/null
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
	[ -f "$filename" ] || return

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
	local num_dupes=0
	[ -f "$filename" ] || return

	if uniq --help 2>&1 | grep -q -- '-D'
	then
		num_dupes="$(sort "$filename" | uniq -D | awk NF | wc -l)"
	else
		while IFS=$' \t\n' read -r dupe_count
		do
			num_dupes="$((num_dupes + dupe_count))"
		done < <(awk NF "$filename" | sort | uniq -c | grep -o '^[[:space:]]*[2-9][0-9]*')
	fi
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
		if [ "$i" == "$((offset-1))" ] || [ "$i" = "$offset" ] || [ "$i" == "$((offset+1))" ]
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
	[ -f ~/.zshrc ] || return

	num_plugin_lists="$(grep -c "^[[:space:]]*plugins=" ~/.zshrc)"
	if [ "$num_plugin_lists" = "0" ]
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

function check_zshrc_zsh_var() {
	local num_sets
	num_sets="$(grep -c '^ZSH=' ~/.zshrc)"
	if [ "$num_sets" -gt 1 ]
	then
		warn "Warning: ZSH is set multiple times in your ~/.zshrc file"
		warn ""
		local zsh_line
		while read -r zsh_line
		do
			warn "       $zsh_line"
		done < <(grep -Hn '^ZSH=' ~/.zshrc)
		warn ""
	fi
	# only when the dotfiles installer ran
	# and sym linked it to the le wagon dotfiles
	# we expect this variable to be set
	if [ -L ~/.zshrc ]
	then
		if [ "$num_sets" -eq 0 ]
		then
			warn "Warning: ZSH is not set in your ~/.zshrc"
		else
			local zsh_value
			zsh_value="$(grep '^ZSH=' ~/.zshrc | tail -n1 | cut -d= -f2-)"
			# shellcheck disable=2016
			if [ "$zsh_value" != '$HOME/.oh-my-zsh' ]
			then
				warn "Warning: ZSH is not set to the correct value in your ~/.zshrc"
				warn "         expected: \$HOME/.oh-my-zsh"
				warn "              got: $zsh_value"
			fi
		fi
	fi
}

function check_zshrc_contents() {
	dbg "checking zshrc ..."
	[ -f ~/.zshrc ] || return

	assert_num_file_lines ~/.zshrc 60 110
	assert_num_dupe_lines ~/.zshrc 6
	check_zshrc_plugins
	check_zshrc_zsh_var

	# shellcheck disable=SC2016
	if ! grep -qF 'source "${ZSH}/oh-my-zsh.sh"' ~/.zshrc
	then
		warn "Warning: oh-my-zsh is not loaded in your ~/.zshrc"
	fi

	if is_data
	then
		# shellcheck disable=2016
		if ! grep -qF 'eval "$(direnv hook zsh)"' ~/.zshrc
		then
			if [ "$arg_fix" = "1" ]
			then
				log "adding direnv zsh hook to zshrc ..."
				echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc
			else
				warn "Warning: missing direnv hook in your zshrc"
				warn "         run the following command to fix it"
				warn ""
				warn "  ${_color_WHITE}echo 'eval \"\$(direnv hook zsh)\"' >> ~/.zshrc"
				warn ""
				warn "         or run the doctor with $_color_WHITE--fix"
				warn ""
			fi
		fi
	fi

	if is_web
	then
		# shellcheck disable=SC2016
		if ! grep -qE '^[^#]*(\.|source) "\$NVM_DIR/nvm.sh"' ~/.zshrc
		then
			warn "Warning: nvm.sh is not loaded in your ~/.zshrc"
		fi
		# shellcheck disable=SC2016
		if ! grep -qF 'eval "$(rbenv init -)"' ~/.zshrc
		then
			warn "Warning: rbenv is not initialized in your ~/.zshrc"
		fi
		if is_windows
		then
			if ! grep -E '[^#]*sudo /etc/init.d/postgresql start' ~/.zshrc
			then
				if [ "$arg_fix" = "1" ]
				then
					if [ ! -f /etc/init.d/postgresql ]
					then
						warn "Warning: /etc/init.d/postgresql file not found"
					else
						log "adding postgres start to zshrc"
						echo "sudo /etc/init.d/postgresql start" >> ~/.zshrc
					fi
				else
					warn "Warning: postgresql is not started in your ~/.zshrc"
					warn "         to fix it automatically"
					warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
				fi
			fi
		fi
	fi

	# shellcheck disable=SC2016
	if ! grep -qE '^[^#]*(\.|source) "\$HOME/.aliases"' ~/.zshrc
	then
		warn "Warning: .aliases not loaded in your ~/.zshrc"
	fi

	if ! grep -Eq '^[[:space:]]*export EDITOR=' ~/.zshrc
	then
		if ! grep -q '[^#]EDITOR=' ~/.zshrc
		then
			warn "Warning: the EDITOR variable is not set in your ~/.zshrc"
		else
			warn "Warning: the EDITOR variable is set in your ~/.zshrc but not exported"
		fi
	elif ! grep -Eq '^[[:space:]]*export EDITOR=["'"'"']?code' ~/.zshrc
	then
		warn "Warning: your EDTIOR variable is not set to code in your ~/.zshrc"
		grep -n '^[^#]*EDITOR=' ~/.zshrc
	fi
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

	# le wagon setup puts the pyenv init in the ~/.zprofile
	# but we should not alert if it moved to ~/.zshrc
	# since that also works just fine
	if ! grep -q '^[[:space:]]*type -a pyenv' ~/.zshrc
	then
		warn "Warning: missing pyenv init in ~/.zprofile"
	fi
}

function check_zprofile_contents() {
	dbg "checking zprofile ..."
	[ -f ~/.zprofile ] || return

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
		if [ "$arg_fix" = "1" ]
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
		pwsh \
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

	if [ "$anti_viruses" = "" ]
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
	dbg -n "checking disk space ..."
	# only check the / partition

	_is_warn_disk=0

	_warn_disk() {
		[ "$_is_warn_disk" = "0" ] && printf '\n'
		warn "Warning: failed to get free disk space"
		_is_warn_disk=1
	}

	local avail
	if is_mac
	then
		if ! avail="$(df -h /System/Volumes/Data | awk '{ print $4 }' | tail -n1)"
		then
			_warn_disk "Warning: failed to get free disk space"
			return
		fi
	else
		if ! avail="$(df -h 2>/dev/null | grep ' /$' | awk '{ print $4 }')"
		then
			_warn_disk "Warning: failed to get free disk space"
			return
		fi
	fi
	if [[ "$avail" =~ ^[0-9]+M$ ]] || [[ "$avail" =~ ^[0-9]+K$ ]]
	then
		_warn_disk "Warning: detected too little free disk space $avail"
	# does not work in bash 3
	# elif [[ "$avail" =~ ^([0-9]+)Gi?$ ]]
	elif echo "$avail" | grep -Eq '^([0-9]+)Gi?$'
	then
		local avail_gb
		# avail_gb="${BASH_REMATCH[1]}"
		avail_gb="$(echo "$avail" | grep -Eo '^([0-9]+)Gi?$' | cut -d'G' -f1)"
		if [ "$avail_gb" -lt "$MIN_DISK_SPACE_GB" ]
		then
			_warn_disk "Warning: you only seem to have $avail_gb GB free disk space"
			_warn_disk "         it is recommended to have more than $MIN_DISK_SPACE_GB GB"
		fi
	else
		_warn_disk "Warning: failed to detect available disk space"
	fi

	[ "$_is_warn_disk" = "0" ] && dbg_echo " $avail${_color_GREEN} OK"
}

function check_rvm() {
	if [ -d ~/.rvm ]
	then
		warn "Warning: rvm folder found ~/.rvm"
		warn "         rvm might be conflicting with rbenv"
		warn "         the Le Wagon setup recommends rbenv over rvm"
		warn "         If you know what you are doing this is fine"
		return
	fi
	if [ -x "$(command -v rvm)" ]
	then
		warn "Warning: rvm executable found"
		warn "         rvm might be conflicting with rbenv"
		warn "         the Le Wagon setup recommends rbenv over rvm"
		warn "         If you know what you are doing this is fine"
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
	dbg "checking rails version ..."
	if [ ! -x "$(command -v rails)" ]
	then
		return
	fi
	# does not work in bash 3
	# if ! [[ "$(rails -v)" =~ Rails\ ([0-9])\..* ]]
	local rails_version
	if ! rails_version="$(rails -v 2>&1)"
	then
		if [[ "$rails_version" = "rbenv: rails: command not found"* ]]
		then
			# rbenv says stuff like:
 			#  rbenv: rails: command not found
			#  The `rails' command exists in these Ruby versions:
			#   2.2.0
			#   2.4.4
			#
			# Handle it like uninstalled
			return
		elif [[ "$rails_version" = "Rails is not currently installed on this system"* ]]
		then
			# Rails is so fame that it gets a full on placeholder
			# even if it is not installed
			# lets not throw a warning that we could not parse that output as rails version
			#
			# Rails is not currently installed on this system. To get the latest version, simply type:
			#
			#     $ sudo gem install rails
			#
			#     You can then rerun your "rails" command.
			return
		else
			# unknown rails in PATH that can not do -v
			warn "Warning: failed to get rails version"
			echo ""
			echo "$rails_version"
			echo ""
		fi
		return
	fi
	if ! echo "$rails_version" | grep -Eq 'Rails\ ([0-9])\..*'
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
	# major_rails_version="${BASH_REMATCH[1]}"
	if ! major_rails_version="$(rails -v | grep -Eo 'Rails\ [0-9]\.' | cut -d' ' -f2 | cut -d'.' -f1)"
	then
		warn "Warning: failed to extract major rails version"
		warn ""
		warn "         $_color_YELLOW$(rails -v)"
		warn ""
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if [ "$major_rails_version" = "" ]
	then
		warn "Warning: extracted empty major rails version"
		warn ""
		warn "         $_color_YELLOW$(rails -v)"
		warn ""
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if [ "$major_rails_version" -ge "$WANTED_RAILS_MAJOR_VERSION" ]
	then
		return
	fi
	if [ "$arg_fix" = "1" ]
	then
		if ! which gem | grep -qF rbenv/shims
		then
			warn "Warning: failed to install rails"
			warn "         because the gem command is not"
			warn "         installed via rbenv"
			return
		fi
		if ! gem install rails
		then
			error "Error: failed to install rails gem"
		fi
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

function cd_into_fullstack_challenges() {
	local git_repos
	local code_dir_username
	code_dir_username="$(basename "$(get_code_user_dir)")"
	[[ "$code_dir_username" != "" ]] || return 1
	local challenges_dir="$HOME/code/$code_dir_username/fullstack-challenges"
	[[ -d "$challenges_dir" ]] || return 1
	cd "$challenges_dir" || return 1

	return 0
}

function check_git_branch_in_fullstack_challenges() {
	cd_into_fullstack_challenges || return
	[ -d .git ] || return

	local branch
	if ! branch="$(git rev-parse --abbrev-ref HEAD)"
	then
		warn "Warning: failed to get fullstack challenges branch"
		warn "         this is probably an issue with the doctor"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	if [ "$branch" = "" ]
	then
		warn "Warning: the fullstack-challenges branch is empty"
		warn "         this is super weird and should not happen"
		warn "         maybe it is a bug with the doctor"
		warn "         please report this issue here"
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi

	if [ "$branch" != "master" ]
	then
		warn "Warning: the active git branch in the challenges repo is not master"
		warn ""
		warn "         found:    ${_color_RED}$branch"
		warn "         expected: ${_color_green}master"
		warn ""
		if [ "$arg_fix" = "1" ]
		then
			if ! git checkout master
			then
				warn "Warning: failed to fix active fullstack challenges branch"
				warn "         please run the following command and check for errors"
				warn " "
				warn "  ${_color_WHITE}cd $PWD"
				warn "  ${_color_WHITE}git checkout master"
				warn ""
			fi
		else
			warn "  ${_color_WHITE}cd $PWD"
			warn "  ${_color_WHITE}git checkout master"
			warn ""
			warn "         or run the doctor with $_color_WHITE--fix"
			warn ""
		fi
	fi
}

function check_git_remote_in_fullstack_challenges() {
	# le wagon setup requires two remotes
	# on for the students fork
	# and one upstream remote to get updates from le wagon
	cd_into_fullstack_challenges || return

	dbg "checking challenges git remote ..."
	dbg "located fullstack challenges at: $_color_green$PWD$_color_RESET"
	local git_remote
	if ! git_remote="$(git remote -v)"
	then
		warn "Warning: failed to get git remote in fullstack challenges"
		warn ""
		warn "         ${_color_WHITE}cd $PWD && git remote -v"
		warn ""
		return
	fi
	local github_username
	if ! github_username="$(get_gh_ssh_username)"
	then
		github_username='STUDENT_GITHUB_NAME'
	fi
	if [ "$git_remote" = "" ]
	then
		warn "Warning: there are no git remotes in $PWD"
		warn "         you can set them with the following command"
		warn ""
		warn "  ${_color_WHITE}cd $PWD"
		warn "  ${_color_WHITE}git remote add origin git@github.com:$github_username/fullstack-challenges.git"
		warn "  ${_color_WHITE}git remote add upstream git@github.com:lewagon/fullstack-challenges.git"
		warn ""
	fi

	# origin remote

	local remote_origin
	if remote_origin="$(echo "$git_remote" | grep -E '^origin[[:space:]]')"
	then
		local origin_issue=0
		if ! echo "$remote_origin" | grep -Eq '^origin[[:space:]]+git@'
		then
			warn "Warning: the challenges origin remote is not using ssh"
			origin_issue=1
		fi
		if ! echo "$remote_origin" | grep -Eq '^origin[[:space:]]+.*github.com'
		then
			warn "Warning: the challenges origin remote is not pointing to github.com"
			origin_issue=1
		fi
		if ! echo "$remote_origin" | grep -Eq '^origin[[:space:]]+.*/fullstack\-challenges'
		then
			warn "Warning: the challenges origin remote is not containing ${_color_WHITE}fullstack-challenges"
			warn "         is there a typo in the repository name?"
			warn "         did the student rename the fullstack challenges repository?"
			origin_issue=1
		fi
		if echo "$remote_origin" | grep -Eq '^origin[[:space:]]+.*[:/]lewagon/'
		then
			warn "Warning: the challenges origin remote is pointing to lewagon"
			warn "         it should point to the students fork instead"
			origin_issue=1
		fi
		if [ "$github_username" != "STUDENT_GITHUB_NAME" ]
		then
			if ! echo "$remote_origin" | grep -Eq "^origin[[:space:]]+.*[:/]$github_username/"
			then
				warn "Warning: the challenges origin remote does not include the assumed github name"
				warn "         expected to see $_color_green$github_username$_color_yellow"
				origin_issue=1
			fi
		fi
		if [ "$origin_issue" = "1" ]
		then
			if [ "$arg_fix" = "1" ]
			then
				log "Fixing fullstack challenges origin remote"
				git remote set-url origin "git@github.com:$github_username/fullstack-challenges.git"
			else
				warn "         your origin remotes look like this:"
				warn ""
				local line
				while read -r line
				do
					warn "         $_color_RED$line"
				done < <(echo "$remote_origin")
				warn ""
				warn "         to fix your origin remote run the following command:"
				warn ""
				warn "  ${_color_WHITE}cd $PWD"
				warn "  ${_color_WHITE}git remote set-url origin git@github.com:$github_username/fullstack-challenges.git"
				warn ""
				warn "         or run the doctor with $_color_WHITE--fix"
				warn ""
			fi
		fi
	else
		if [ "$arg_fix" = "1" ]
		then
			log "Adding fullstack challenges origin remote"
			git remote add origin "git@github.com:$github_username/fullstack-challenges.git"
		else
			warn "Warning: there is no ${_color_WHITE}origin$_color_yellow remote in $_color_WHITE$PWD"
			warn "         you can add it with the following command:"
			warn ""
			warn "  ${_color_WHITE}cd $PWD"
			warn "  ${_color_WHITE}git remote add origin git@github.com:$github_username/fullstack-challenges.git"
			warn ""
			warn "         or run the doctor with $_color_WHITE--fix"
			warn ""
		fi
	fi

	# upstream remote

	local remote_upstream
	if remote_upstream="$(echo "$git_remote" | grep -E '^upstream[[:space:]]')"
	then
		local upstream_issue=0
		if ! echo "$remote_upstream" | grep -Eq '^upstream[[:space:]]+git@'
		then
			warn "Warning: the challenges upstream remote is not using ssh"
			upstream_issue=1
		fi
		if ! echo "$remote_upstream" | grep -Eq '^upstream[[:space:]]+.*github.com'
		then
			warn "Warning: the challenges upstream remote is not pointing to github.com"
			upstream_issue=1
		fi
		if ! echo "$remote_upstream" | grep -Eq '^upstream[[:space:]]+.*/fullstack\-challenges'
		then
			warn "Warning: the challenges upstream remote is not containing ${_color_WHITE}fullstack-challenges"
			warn "         is there a typo in the repository name?"
			upstream_issue=1
		fi
		if ! echo "$remote_upstream" | grep -Eq '^upstream[[:space:]]+.*[:/]lewagon/'
		then
			warn "Warning: the challenges upstream remote is not pointing to lewagon"
			upstream_issue=1
		fi
		if [ "$upstream_issue" = "1" ]
		then
			if [ "$arg_fix" = "1" ]
			then
				log "Fixing fullstack challenges upstream remote"
				git remote set-url upstream git@github.com:lewagon/fullstack-challenges.git
			else
				warn "         your upstream remotes look like this:"
				warn ""
				local line
				while read -r line
				do
					warn "         $_color_RED$line"
				done < <(echo "$remote_upstream")
				warn ""
				warn "         to fix your upstream remote run the following command:"
				warn ""
				warn "  ${_color_WHITE}cd $PWD"
				warn "  ${_color_WHITE}git remote set-url upstream git@github.com:lewagon/fullstack-challenges.git"
				warn ""
				warn "         or run the doctor with $_color_WHITE--fix"
				warn ""
			fi
		fi
	else
		if [ "$arg_fix" = "1" ]
		then
			log "Adding fullstack challenges upstream remote"
			git remote add upstream git@github.com:lewagon/fullstack-challenges.git
		else
			warn "Warning: there is no ${_color_WHITE}upstream$_color_yellow remote in $_color_WHITE$PWD"
			warn "         you can add it with the following command:"
			warn ""
			warn "  ${_color_WHITE}cd $PWD"
			warn "  ${_color_WHITE}git remote add upstream git@github.com:lewagon/fullstack-challenges.git"
			warn ""
			warn "         or run the doctor with $_color_WHITE--fix"
			warn ""
		fi
	fi
}

function is_wanted_git_repo() {
	local git_repo="$1"
	[ "$git_repo" = './.git' ] && return 0
	[[ "$git_repo" = *05-Push-on-Github-Pages* ]] && return 0
	return 1
}

function check_git_init_in_fullstack_challenges() {
	# if a student types `git init`
	# in the challenges folder
	# can happen on setup day while testing git
	# it overwrites the outer git folder
	# and breaks commands such as `git pull`
	# and `git push` because the remotes are gone
	cd_into_fullstack_challenges || return

	if ! git_repos="$(find . -type d -name .git)"
	then
		warn "Warning: failed to check git repos in fullstack-challenges"
		warn "         this is a issue with the doctor. Please report it here:"
		warn ""
		warn "         https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi

	if [ ! -d ./.git ]
	then
		warn "Warning: missing git folder in fullstack-challenges folder"
		warn "         $(pwd)"
	fi
	local all_good=1
	while IFS= read -r -d '' git_repo
	do
		if ! is_wanted_git_repo "$git_repo"
		then
			all_good=0
			break
		fi
	done < <(find . -type d -name .git -print0)

	[ "$all_good" = "1" ] && return

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
			is_wanted_git_repo "$git_repo" && continue

			warn "           $_color_RED$git_repo$_color_RESET"
		done < <(find . -type d -name .git -print0)
		warn ""
		warn "         This breaks ${_color_WHITE}git push$_color_yellow and other"
		warn "         git commands in these folders. The fix is to"
		warn "         delete these git repos like so:"
		warn ""
		while IFS= read -r -d '' git_repo
		do
			is_wanted_git_repo "$git_repo" && continue

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

function check_c_compiler() {
	dbg "checking C compiler ..."
	# TODO: test this. I just assumed this works.
	if is_mac && (clang++;clang;g++;gcc) 2>&1 | grep -q "missing xcrun"
	then
		error "Error: macOS developer tools seem broken!"
		error "       try reinstalling them using this command"
		error ""
		error "       ${_color_WHITE}xcode-select --install"
		error ""
		return
	fi
	if g++ 2>&1 | grep -q "no input files" && gcc 2>&1 | grep -q "no input files"
	then
		return
	fi
	if clang++ 2>&1 | grep -q "no input files" && clang 2>&1 | grep -q "no input files"
	then
		return
	fi
	if is_web
	then
		sudo apt-get install -y build-essential tklib zlib1g-dev libssl-dev libffi-dev libxml2 libxml2-dev libxslt1-dev libreadline-dev
	fi
}

function check_locale() {
	dbg "checking locale ..."
	if ! locale 2>&1 | grep -q "No such file or directory"
	then
		return
	fi
	sudo locale-gen "en_US.UTF-8"
	sudo dpkg-reconfigure --frontend=noninteractive locales
	sudo update-locale LANG=en_US.UTF-8
}

function check_browser_env() {
	dbg "checking BROWSER ..."
	# on mac browsers usually just work
	is_mac && return

	# Do not assume zshrc was correctly sourced since we are
	# a bash script
	# if [ "$BROWSER" != "" ]
	# then
	# 	if [ ! -f "$BROWSER" ]
	# 	then
	# 		warn "Warning: your BROWSER points to: $_color_RED$BROWSER"
	# 		warn "         but there is no file found at that location"
	# 		warn "         check your ~/.zshrc file and update the BROWSER"
	# 		warn "         to point to your actual browser executable"
	# 	fi
	# 	return
	# fi
	if grep -qE '[^#]*BROWSER' ~/.zshrc
	then
		return
	fi
	if grep -qE '[^#]*BROWSER' ~/.zprofile
	then
		return
	fi
	local browser_paths
	local browser_path
	browser_paths=(
		'/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe'
		'/mnt/c/Program Files/Google/Chrome/Application/chrome.exe'
		'/mnt/c/Program Files (x86)/Mozilla Firefox/firefox.exe'
		'/mnt/c/Program Files/Mozilla Firefox/firefox.exe'
		'/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
		'/usr/bin/chromium'
		'/usr/bin/firefox'
	)
	for browser_path in "${browser_paths[@]}"
	do
		[ -f "$browser_path" ] || continue

		local exe
		exe="${browser_path##*/}"
		log "Setting $_color_GREEN$exe$_color_RESET as BROWSER"
		echo "export BROWSER=\"$browser_path\"" >> ~/.zshrc
		echo "export GH_BROWSER=\"'$browser_path'\"" >> ~/.zshrc
		return
	done

	warn "Warning: did not find any browser exe on your system"
}

function check_rubygems() {
	dbg "checking rubygems.org ..."
	# only check rubygems if ruby is installed
	[ -x "$(command -v ruby)" ] || return

	if curl -Lks 'https://git.io/rg-ssl' | ruby &>/dev/null
	then
		# connectivity to rubygems.org works
		return
	fi
	local ipv4_fallback=0
	if [ -f ~/.gemrc ] && grep -q ":ipv4_fallback_enabled: true" ~/.gemrc
	then
		ipv4_fallback=1
	fi
	if [ "$arg_fix" = "1" ]
	then
		if [ "$ipv4_fallback" = "0" ]
		then
			log "Enabling ipv4 fallback for rubygems.org ..."
			echo ":ipv4_fallback_enabled: true" >> ~/.gemrc
		else
			log "ipv4 fallback already enabled for rubygems.org"
		fi
	else
		error "Error: failed to connect to rubygems.org"
		if [ "$ipv4_fallback" = "0" ]
		then
			error "       this may be fixed with the ipv4 fallback option"
			error "       you can enable that by running the following command:"
			error ""
			error "         ${_color_WHITE}echo \":ipv4_fallback_enabled: true\" >> ~/.gemrc"
			error ""
			error "       or run the doctor with $_color_WHITE--fix"
			error ""
		fi
	fi
}

function check_jupyter_config() {
	dbg "checking jupyter config ..."
	is_windows || return
	[ -x "$(command -v jupyter)" ] || return

	local py_cfg="$HOME/.jupyter/jupyter_notebook_config.py"
	if [ ! -f "$py_cfg" ]
	then
		warn "Warning: did not find jupyter config file $_color_red$py_cfg"
		warn "         try running this command:"
		warn ""
		warn "           ${_color_WHITE}jupyter notebook --generate-config"
		warn ""
		return
	fi
	if ! python -m py_compile "$py_cfg"
	then
		warn "Warning: seems like there is a syntax issue in your jupyter config"
		warn "         have a look at the file"
		warn ""
		warn "           ${_color_WHITE}code $py_cfg"
		warn ""
		return
	fi
	if ! grep -q '^c.NotebookApp.use_redirect_file = False' "$py_cfg"
	then
		warn "Warning: did not find redirect being set to false in your jupyter config"
		warn "         make sure to add the following line to the file:"
		warn ""
		warn "           ${_color_green}c.NotebookApp.use_redirect_file = False"
		warn ""
		warn "         edit the file with the following command"
		warn ""
		warn "           ${_color_WHITE}code $py_cfg"
		warn ""
	fi
}

function check_dotfiles_version() {
	dbg "checking dotfiles version ..."
	local dotfiles_dir=''
	dotfiles_dir="$(get_code_user_dir)"
	if [ ! -d "$dotfiles_dir" ] || [ "$dotfiles_dir" == "" ]
	then
		return
	fi
	cd "$dotfiles_dir"/dotfiles || { error "Error: something went wrong"; exit 1; }

	[ -x "$(command -v git)" ] || return
	if [ ! -d .git ]
	then
		warn "Warning: there is no .git folder in $_color_WHITE$PWD"
		warn "         that is weird but might be okay if you know what you do"
		return
	fi

	if ! git rev-parse -q --verify "$WANTED_DOTFILES_SHA^{commit}" > /dev/null
	then
		local github_username=''
		if ! github_username="$(get_gh_ssh_username)"
		then
			github_username='yourusername'
		fi
		warn "Warning: seems like your dotfiles are outdated"
		warn "         goto https://github.com/$github_username/dotfiles in your browser"
		warn "         and click on sync fork"
		warn "         and then run this command:"
		warn ""
		warn "           ${_color_WHITE}cd $PWD && git pull"
		warn ""
		is_dotfiles_old=1
	fi
}

function check_web_gh_webhook() {
	dbg "checking github webhook ..."
	[ -x "$(command -v gh)" ] || return
	[ -x "$(command -v jq)" ] || return

	local github_username
	if ! github_username="$(get_gh_cli_username)"
	then
		error "Error: failed to get github username from gh cli"
		error "       please run the following command to authenticate"
		error "       on github"
		error ""
		error "         ${_color_WHITE}gh auth login -s 'user:email' -w"
		error ""
		return
	fi

	if [ "$github_username" == "" ]
	then
		error "Error: github name is empty. This is probably a bug of the doctor."
		error "       please report this issue here"
		error ""
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		return
	fi
	local hooks_json
	if ! hooks_json="$(gh api "repos/$github_username/fullstack-challenges/hooks" 2> /dev/null)"
	then
		# assume repo is not forked if this fails
		return
	fi
	if [ "$hooks_json" = "[]" ]
	then
		warn "Warning: there is no webhook found in your fullstack repo"
		warn "         https://github.com/$github_username/fullstack-challenges/settings/hooks"
		warn ""
		warn "         did you possibly delete your fullstack-challenges repository?"
		warn "         please contact the kitt engineering team to request a webhook reset"
		return
	fi
	local num_hooks
	num_hooks="$(echo "$hooks_json" | jq '[.[] | select(.config.url == "https://kitt.lewagon.com/github_webhooks")] | length')"
	if [ "$num_hooks" -gt "1" ]
	then
		warn "Warning: you have multiple kitt hooks on your fullstack repo"
		warn "         https://github.com/$github_username/fullstack-challenges/settings/hooks"
		warn "         that may not be a problem but is a bit weird."
		return
	fi
	if [ "$num_hooks" -eq "0" ]
	then
		warn "Warning: there is no lewagon webhook found in your fullstack repo"
		warn "         https://github.com/$github_username/fullstack-challenges/settings/hooks"
		warn ""
		warn "         other webhooks were found. Did you maybe edit your webhook?"
		return
	fi
}

# if ! gh_email="$(gh api user/emails | jq '.[] | select(.primary==true) | .email' -r)"
# then
# 	log "got github cli email $gh_email"
# fi
function gh_email_primary() {
	if [ "$g_github_cli_email" = null ]
	then
		return 1
	fi
	if [ "$g_github_cli_email" != "" ]
	then
		printf '%s' "$g_github_cli_email"
		return 0
	fi

	local scopes
	scopes="$(get_gh_scopes)" || return 1
	if ! printf '%s' "$scopes" | grep -q ' user:email'
	then
		return 1
	fi

	if ! g_github_cli_email="$(gh api user/emails | jq '.[] | select(.primary==true) | .email' -r)"
	then
		g_github_cli_email=null
		return 1
	fi
	if [ "$g_github_cli_email" = "" ]
	then
		g_github_cli_email=null
		return 1
	fi
	printf '%s' "$g_github_cli_email"
	return 0
}

function get_gh_scopes() {
	local gh_status=''
	if ! gh_status="$(gh_auth_status)"
	then
		return 1
	fi
	if ! printf '%s' "$gh_status" | grep -o 'Token scopes:.*' | cut -d':' -f2-
	then
		exit 1
	fi
}

function check_gh_email_public_and_matching() {
	[ -x "$(command -v gh)" ] || return
	[ -x "$(command -v jq)" ] || return
	dbg "checking github email visibility ..."

	local gh_status=''
	if ! gh_status="$(gh_auth_status)"
	then
		return
	fi
	local scopes
	if ! scopes="$(get_gh_scopes)"
	then
		error "Error: failed to get github cli scopes"
		error "       this is likley an issue with the doctor it self"
		error "       please report it here"
		error ""
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		error ""
		exit 1
	fi
	if ! [[ "$scopes" == *" user:email"* ]]
	then
		warn "Warning: your github cli does not have the user:email scope"
		warn "         that is fine if you know what you are doing"
		warn "         to grant that access you can run the following command"
		warn ""
		warn "           ${_color_WHITE}gh auth refresh -h github.com -s user:email"
		warn ""
		return
	fi
	local gh_email
	local gh_visibility
	if ! gh_email="$(gh_email_primary)"
	then
		warn "Warning: failed to get github cli primary email"
		warn "         this is likley an issue with the doctor it self"
		warn "         please report it here"
		warn ""
		warn "          https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		return
	fi
	if [ "$gh_email" = "[]" ] || [ "$gh_email" = "null" ]
	then
		warn "Warning: your github email is empty"
		return
	fi
	if ! gh_visibility="$(gh api user/emails | jq '.[] | select(.primary==true) | .visibility' -r)"
	then
		warn "Warning: failed to get github cli email visibility"
		warn "         this is likley an issue with the doctor it self"
		warn "         please report it here"
		warn ""
		warn "          https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		return
	fi
	if [ "$gh_visibility" = "private" ]
	then
		warn "Warning: your github email visibility is set to private"
		warn "         this might cause issues if github blocks you from publishing it"
		warn "         with git pushes. If you can push to fullstack challenges just fine"
		warn "         ignore this warning."
		warn "         If your pushing does not work untick this option in your settings"
		warn ""
		warn "         ${_color_green}https://github.com/settings/emails"
		warn "         ${_color_bg_white}${_color_BLACK}[ ] Block command line pushes that expose my email"
		warn ""
		return
	fi
	local git_email
	if ! git_email="$(git config --global user.email)"
	then
		warn "Warning: failed to get git email"
		warn "         this is likley an issue with the doctor it self"
		warn "         please report it here"
		warn ""
		warn "          https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		return
	fi
	if [ "$gh_email" = "$git_email" ]
	then
		log "Found git email $_color_green$git_email"
		return
	fi
	warn "Warning: your git email does not match your github one"
	warn "            git: $_color_RED$git_email"
	warn "         github: $_color_RED$gh_email"
	if [ "$arg_fix" = "1" ]
	then
		log "updating git email to be '$gh_email' ..."
		git config --global user.email "$gh_email"
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
		warn "         ${_color_WHITE}git config --global user.email \"$gh_email\""
		warn "         ${_color_WHITE}git commit --allow-empty -m \"New commit with fixed email\""
		warn "         ${_color_WHITE}git push origin master"
		warn ""
		warn "         to fix it automatically"
		warn "         run the doctor with the $_color_WHITE --fix $_color_yellow flag"
	fi
}

# uses heuristics to assume the correct email
# trying to avoid false positives when the student has multiple github accounts
#
# if email="$(guess_git_email_or_empty)"
# then
#   log "the doctor assumes your git email should be $email"
# fi
function guess_git_email_or_empty() {
	local ssh_username
	local cli_username
	if ! ssh_username="$(get_gh_ssh_username)"
	then
		return 1
	fi
	if cli_username="$(get_gh_cli_username)"
	then
		return 1
	fi
	# if there are two accounts on the system
	# do not assume which one is correct
	[ "$ssh_username" = "$cli_username" ] || return 1

	local gh_email
	if ! gh_email="$(gh_email_primary)"
	then
		return 1
	fi

	printf '%s' "$gh_email"
	return 0
}

# prints a warning and throws a non zero return code
# if the git config user.email is not set
#
# if ! check_git_email_set
# then
#   error "Error: email not set"
# fi
function check_git_email_set() {
	dbg "checking git email set ..."
	# do not warn about unset emails if the user is not logged in yet
	# otherwise this will always show when the setup is currently in progress
	if ! gh_auth_status > /dev/null
	then
		return 0
	fi

	local git_email
	if ! git_email="$(git config --global user.email)"
	then
		warn "Warning: failed to get git email"
		warn "         this is likley an issue with the doctor it self"
		warn "         please report it here"
		warn ""
		warn "          https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		return 0
	fi

	if [ "$git_email" = "" ]
	then
		warn "Warning: there is no git email set yet"
		return 1
	fi

	return 0
}

function check_git_email_valid_regex() {
	dbg "checking git email valid ..."

	local git_email
	if ! git_email="$(git config --global user.email)"
	then
		warn "Warning: failed to get git email"
		warn "         this is likley an issue with the doctor it self"
		warn "         please report it here"
		warn ""
		warn "          https://github.com/ElvisDot/lewagon-setup/issues"
		warn ""
		return 1
	fi

	[ "$git_email" = "" ] && return

	local suggested_email
	if ! suggested_email="$(guess_git_email_or_empty)"
	then
		suggested_email=YOUR_EMAIL
	fi

	if ! printf '%s' "$git_email" | grep -Eq '.+@.+'
	then
		warn "Warning: your git email does not contain an @ sign"
		warn "         your currently set git email is: ${_color_RED}$git_email"
		warn "         is that the email you used for github? If not you can update it with"
		warn ""
		warn "  ${_color_WHITE}git config --global user.email $suggested_email"
		warn ""
	fi

	if printf '%s' "$git_email" | grep -Eq 'example.com'
	then
		warn "Warning: your git email does contain ${_color_RED}example.com"
		warn "         your currently set git email is: ${_color_RED}$git_email"
		warn "         is that the email you used for github? If not you can update it with"
		warn ""
		warn "  ${_color_WHITE}git config --global user.email $suggested_email"
		warn ""
	fi
}

function check_rubocop() {
	dbg "checking rubocop ..."
	[ -x "$(command -v rubocop)" ] || return

	# TODO: run 'rubocop -d' in the challenges repo
	# 	then verify that the correct configs are loaded and no additonal ones
	# 	but ensure that it does not start linting the challenges

	if [ -f ~/.rubocop.yml ]
	then
		warn "Warning: found $_color_RED~/.rubocop.yml"
		warn "         this user wide rubocop config could mess with the"
		warn "         le wagon challenges rubocop config."
		warn "         If you know what you are doing this is fine"
	fi
}

function _run_data_script() {
	local script_cmd="$1"
	local tmp_log
	if ! tmp_log="$(mktemp /tmp/lewagon_doctor_XXXXXXX.txt)"
	then
		error "Error: failed to use mktemp"
		return
	fi
	if ! eval "$script_cmd" &> "$tmp_log"
	then
		cat "$tmp_log"; rm "$tmp_log"
		error "Error: failed to run official Le Wagon data setup check script"
		error "       please run the following command and check for errors:"
		error ""
		error "  ${_color_WHITE}$script_cmd"
		error ""
		[ -f "$tmp_log" ] && rm "$tmp_log"; return
	fi
	if grep -q '❌' "$tmp_log"
	then
		cat "$tmp_log"; rm "$tmp_log"
		error "Error: failed to run official Le Wagon data setup check script"
		error "       please run the following command and check for ❌ errors:"
		error ""
		error "  ${_color_WHITE}$script_cmd"
		error ""
		[ -f "$tmp_log" ] && rm "$tmp_log"; return
	fi
	if ! grep -q '✅' "$tmp_log"
	then
		cat "$tmp_log"; rm "$tmp_log"
		error "Error: failed to run official Le Wagon data setup check script"
		error "       missed a checkmark ✅ in the output of the following command:"
		error ""
		error "  ${_color_WHITE}$script_cmd"
		error ""
		return
	fi
	[ -f "$tmp_log" ] && rm "$tmp_log"; return
}

function check_data_official_lewagon_checks() {
	dbg "running Le Wagon data check scripts ..."
	# https://github.com/lewagon/data-setup/blob/efe82062ec304f1bfc3489594e37c269a1213166/WINDOWS.md#python-setup-check-up

	_run_data_script $'zsh -c "$(curl -fsSL https://raw.githubusercontent.com/lewagon/data-setup/master/checks/python_checker.sh)" '"$WANTED_PYTHON_VERSION"
	_run_data_script $'zsh -c "$(curl -fsSL https://raw.githubusercontent.com/lewagon/data-setup/master/checks/pip_check.sh)"'
	_run_data_script $'python -c "$(curl -fsSL https://raw.githubusercontent.com/lewagon/data-setup/master/checks/pip_check.py)"'
}

function check_conda() {
	dbg "checking conda ..."

	[ ! -x "$(command -v conda)" ] && return

	warn "Warning: found ${_color_RED}conda${_color_yellow} in your PATH"
	warn "         Le Wagon recommends to use pyenv and it might conflict with conda"
	warn "         If you know what you are doing this is fine"
}

function check_pyenv_installed() {
	dbg "checking pyenv installed ..."

	[ -d ~/.pyenv ] && return

	log "installing pyenv ..."
	git clone https://github.com/pyenv/pyenv.git ~/.pyenv
}

function check_python_build_deps() {
	dbg "checking python build dependencies ..."

	is_ubuntu || return

	local installed_packages
	local wanted_packages
	local num_wanted_packages

	installed_packages="$(apt-cache search . | cut -d' ' -f1)"
	wanted_packages="make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev"
	wanted_packages="$wanted_packages wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev python3-dev"
	num_wanted_packages="$(printf '%s' "$wanted_packages" | grep -o . | grep -c ' ')"

	local i=0
	local missing=0
	while [ "$i" -le "$num_wanted_packages" ]
	do
		i="$((i + 1))"
		wanted_package="$(printf '%s' "$wanted_packages" | cut -d' ' -f"$i")"

		if ! printf '%s\n' "$installed_packages" | grep -qxF "$wanted_package"
		then
			missing=1
			break
		fi
	done

	[ "$missing" = "0" ] && return

	log "Installing missing apt packages to build python ..."

	sudo apt-get update
	# shellcheck disable=SC2086
	sudo apt-get install -y $wanted_packages
}

function check_pyenv_virtualenv() {
	dbg "checking pyenv virtualenv ..."

	[ ! -x "$(command -v pyenv)" ] && return

	local envs
	if ! envs="$(pyenv virtualenvs)"
	then
		error "Error: failed to run ${_color_WHITE}pyenv virtualenvs"
		return
	fi
	# shellcheck disable=SC2063
	if ! echo "$envs" | grep -q '* lewagon '
	then
		log " ➜ ${_color_WHITE}pyenv virtualenvs"
		echo "$envs"
		error "Error: ${_color_yellow}lewagon${_color_red} is not set as your virtualenv"
	fi
}

function check_ohmyzsh() {
	dbg "checking oh-my-zsh ..."

	# TODO: check if the folder is not empty
	#       check if it contains correct files
	#       check if it is corrupted and the install would fail
	#       as a fix suggest deleting it. Before suggesting that
	#       check if there are custom plugins/themes/prompts or similar
	#
	#	it being loaded is already checked in the zshrc check
	[ -d ~/.oh-my-zsh ] && return

	if ! sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
	then
		# that usually fails when its already there and not empty
		warn "Warning: failed to install oh-my-zsh"
		warn "         please run the following command and check for errors"
		warn ""
		warn "  ${_color_WHITE}sh -c \"\$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\""
		warn ""
	fi
}

function check_gems() {
	dbg "checking gems ..."

	[ ! -x "$(command -v ruby)" ] && return

	local check_gems_script
	read -r -d '' check_gems_script <<-EOF
	REQUIRED_GEMS = %w[colored faker http pry-byebug rake rails rest-client rspec rubocop-performance sqlite3]
	MINIMUM_AVATAR_SIZE = 2 * 1024

	REQUIRED_GEMS.each do |the_gem|
	  begin
	    require the_gem
	  rescue LoadError
	    puts "         The gem '${_color_YELLOW}#{the_gem}${_color_yellow}' is missing."
	    puts "         To fix it run this command"
	    puts ""
	    puts "  ${_color_WHITE}gem install #{REQUIRED_GEMS.join(" ")}"
	    exit 1
	  end
	end
	EOF
	local missing_gems_lines
	if ! missing_gems_lines="$(ruby -e "$check_gems_script")"
	then
		warn "Warning: missing gems"
		printf '%b\n' "$missing_gems_lines" | while IFS='' read -r line
		do
			warn "$line"
		done
		warn ""
	fi
}

function check_brew_capstone() {
	dbg "checking capstone ..."

	is_mac || return
	if ! brew list capstone 2>/dev/null | grep capstone &>/dev/null
	then
		return
	fi

	# https://github.com/rbenv/ruby-build/discussions/2347
	warn "Warning: you have capstone installed. This might break the ruby build"
	warn "         if you have trouble running this command $_color_WHITE rbenv install 3.1.2"
	warn "         you can try uninstalling capstone."
	warn ""
	warn "  ${_color_WHITE}brew uninstall capstone"
	warn ""
}

# shows a warning if the provided git path
# is in state merging or rebasing
function check_git_rebase() {
	local git_dir="$1"
	if [ "$git_dir" = "" ] || [ ! -d "$git_dir" ]
	then
		error "Error: invalid git dir '$git_dir'"
		error "       this is an issue with the doctor please report it here"
		error ""
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		exit 1
	fi
	if ! printf '%s' "$git_dir" | grep -q '\.git$'
	then
		error "Error: invalid git dir '$git_dir'"
		error "       this is an issue with the doctor please report it here"
		error ""
		error "       https://github.com/ElvisDot/lewagon-setup/issues"
		exit 1
	fi

	# https://repo.or.cz/w/git.git/blob/1e6f5b22ad318446500fbd3b94b733eddd5b6414:/contrib/completion/git-prompt.sh#l377
	if [ -d "$git_dir"/rebase-merge/ ]
	then
		warn "Warning: git repo in state merging $_color_RED$git_dir"
	fi
	if [ -d "$git_dir"/rebase-apply/ ]
	then
		warn "Warning: git repo in state rebase $_color_RED$git_dir"
	fi
}

function check_git_repos_merging() {
	dbg "check git repos merging ..."

	if is_web
	then
		cd_into_fullstack_challenges || return
		check_git_rebase "$PWD/.git"
	fi

	local dotfiles_dir=''
	dotfiles_dir="$(get_code_user_dir)"
	if [ ! -d "$dotfiles_dir" ] || [ "$dotfiles_dir" == "" ]
	then
		return
	fi
	dotfiles_dir="$dotfiles_dir/dotfiles/.git"
	if [ -d "$dotfiles_dir" ]
	then
		check_git_rebase "$dotfiles_dir"
	fi
}

function check_linux_clock() {
	dbg "checking linux clock ..."

	is_mac && return
	[ -x "$(command -v timedatectl)" ] || return

	if ! timedatectl | grep -q 'NTP service: active'
	then
		warn "Warning: your NTP service is not active."
		warn "         This might not be an issue if your clock is running correctly"
		warn "         but if your clock is out of sync too much you might get some"
		warn "         certificate not valid yet errors."
		warn ""
		warn "         is this date correct?"
		warn "         $_color_magenta$(date)"
		warn ""
	fi
}

function check_rubygems_version() {
	dbg "checking rubygems version ..."

	# only update rubygems if it is installed with rbenv
	# do not mess with any other system
	if [[ ! "$(command -v ruby)" =~ shims ]]
	then
		return
	fi

	local gem_version
	if ! gem_version="$(gem --version)"
	then
		warn "Warning: failed to get rubygems version"
		return
	fi

	# if we are the wanted version we are good
	# but also if we are more recent than the wanted version we are good
	if semver_ge "$gem_version" "$WANTED_RUBYGEMS_VERSION" rubygems
	then
		dbg "got rubygems version $_color_GREEN$gem_version"
		return
	fi

	log "found outdated rubygems version $_color_yellow$gem_version$_color_RESET updating ..."
	if ! gem update --system
	then
		warn "Warning: failed to update rubygems"
	fi
}

function activerecord_connect_sqlite3() {
	ruby -e '
	require "active_record"
	require "sqlite3"
	ActiveRecord::Base.configurations = {"development"=>{"adapter"=>"sqlite3", "database"=>"/tmp/doctor_test.sqlite3"}}
	ActiveRecord::Base.establish_connection(:development)
	'
}
function activerecord_connect_sqlite3_v1() {
	ruby -e '
	require "active_record"
	gem "sqlite3", "~> 1.0"
	require "sqlite3"
	ActiveRecord::Base.configurations = {"development"=>{"adapter"=>"sqlite3", "database"=>"/tmp/doctor_test.sqlite3"}}
	ActiveRecord::Base.establish_connection(:development)
	'
}

# returns the first full semantic version of the installed sqlite3 gem
# only looking at version 2.x.x
#
# for example: 2.0.0
#
function sqlite3_gem_v2() {
	gem list sqlite3 | grep -oE '[^0-9]2\.[0-9]+\.[0-9]' | cut -c2- | head -n1
}

function check_activerecord() {
	dbg "checking activerecord ..."
	if ! activerecord_connect_sqlite3 &>/dev/null
	then
		if [ "$arg_verbose" -gt 0 ]
		then
			activerecord_connect_sqlite3
		fi
		# the v1 error is not interesting
		if activerecord_connect_sqlite3_v1
		then
			local sqlite3_version
			if sqlite3_version="$(sqlite3_gem_v2)"
			then
				if [ "$sqlite3_version" != "" ]
				then
					# TODO: remove this pyramid of death as soon as active record works with sqlite3 v2
					if [ "$arg_fix" = 1 ]
					then
						log "uninstalling sqlite3 version $sqlite3_version which breaks activerecord ..."
						gem uninstall sqlite3 --version "$sqlite3_version"
					else
						warn "Warning: failed to use activerecord with sqlite3"
						warn "         but using it with sqlite3 version 1.x.x works"
						warn "         try uninstalling sqlite3 $_color_RED$sqlite3_version$_color_yellow"
						warn "         which seems to be incompatible with activerecord"
						warn ""
						warn "  ${_color_WHITE}gem uninstall sqlite3 --version $sqlite3_version"
						warn ""
						warn ""
						warn "         or run the doctor with $_color_WHITE--fix"
						warn ""
					fi
					return
				fi
			fi
		fi
		warn "Warning: failed to use activerecord with sqlite3"
		warn "         try updating and or uninstalling all versions of activerecord and sqlite3"
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
		check_brew_capstone
	elif is_windows
	then
		check_windows_anti_virus
	fi
	check_vscode
	detect_bootcamp
	# check_path_overwritten
	check_package_manager_programs
	check_gh_cli
	check_github_access
	check_dotfiles_version
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
			check_web_gh_webhook
		fi
	fi
	check_gh_email_public_and_matching
	if check_git_email_set
	then
		check_git_email_valid_regex
	fi
	check_git_repos_merging
	check_zshrc_contents
	check_zprofile_contents
	check_c_compiler
	check_locale
	check_browser_env
	check_ohmyzsh
	check_linux_clock
	if is_web
	then
		check_vscode_extensions_web
		check_ruby
		check_rubygems_version
		check_activerecord
		check_rvm
		check_asdf_ruby
		check_rails_version
		check_database
		check_ready_commit_email
		check_git_init_in_fullstack_challenges
		check_git_remote_in_fullstack_challenges
		check_git_branch_in_fullstack_challenges
		check_rubygems
		check_rubocop
		check_gems
	elif is_data
	then
		check_docker
		check_asdf_python
		check_jupyter_config
		check_conda
		check_data_official_lewagon_checks
		check_pyenv_installed
		check_python_build_deps
		check_pyenv_virtualenv
	fi
	if [ "$num_errors" = "0" ] && [ "$num_warnings" = "0" ]
	then
		log "✅$_color_GREEN your system is healthy"
	else
		log "Summary warnings: $num_warnings errors: $num_errors"
	fi
}

main
