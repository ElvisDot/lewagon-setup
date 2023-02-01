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
arg_unix_name=""

bootcamp=unkown

num_warnings=0
num_errors=0

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
	printf '%b[%b-%b]%b %s%b\n' "$_color_WHITE" "$_color_RED" "$_color_WHITE" "$_color_red" "$msg" "$_color_RESET"
}

function warn() {
	local msg="$1"
	if [[ "$msg" =~ Warning: ]]
	then
		num_warnings="$((num_warnings + 1))"
	fi
	printf '%b[%b!%b]%b %b%b\n' "$_color_WHITE" "$_color_YELLOW" "$_color_WHITE" "$_color_yellow" "$msg" "$_color_RESET"
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
		winver="$(powershell.exe -c "[System.Environment]::OSVersion.Version.Major")"
		# note that winver is 10 on windows 11 but it is less than 10 on windows 8
		if [ "$winver" -lt "10" ]
		then
			warn "Warning: your windows is outdated please do a update"
		fi
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

	rvm implode &>/dev/null
	if [ -d ~/.rvm ]
	then
		sudo rm -rf ~/.rvm
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

function wanted_ruby_version() {
	# We could get the latest version from here
	#
	# curl -s https://raw.githubusercontent.com/lewagon/setup/master/check.rb | grep "^REQUIRED_RUBY_VERSION" | cut -d'"' -f2
	#
	# but doing http requests is slow
	# so maybe add this to the CI
	# or only if some last_updated variable
	# is more than x days ago
	echo "3.1.2"
}

function is_outdated_ruby() {
	local check="$1"
	local wanted
	wanted="$(wanted_ruby_version)"
	# strip dots and turn it into a comparable number
	# 3.1.2 -> 312
	wanted="${wanted//./}"
	check="${check//./}"
	[[ "$check" -lt "$wanted" ]] && return 0
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

	local ruby_vers
	ruby_vers="$(ruby -e "puts RUBY_VERSION" 2>/dev/null)"

	if is_outdated_ruby "$ruby_vers"
	then
		if [ "$arg_fix" == "1" ]
		then
			install_ruby
		else
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
		error "       https://github.com/lewagon/setup/blob/master/macos.md#dotfiles-standard-configuration"
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
	if [ "$found_dotfiles" == "1" ] && grep -q "rbenv init" ~/.zshrc
	then
		return 0
	fi
	return 1
}

function check_docker() {
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
				# todo: auto fix this
				error "Error: your ~/.ssh/config points to a invalid identity file"
				error "       $ident"
				exit 1
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
			exit 1
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

function check_database() {
	# todo: check that the user was created and its enabled
	if is_mac
	then
		if [ ! -x "$(command -v sqlite3)" ]
		then
			brew install sqlite
		fi
		if [ ! -x "$(command -v psql)" ]
		then
			brew install postgresql
			brew services start postgresql
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

	file_lines="$(wc -l "$filename" | cut -d ' ' -f1)"
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

	local num_dupes
	num_dupes="$(sort "$filename" | uniq -D | awk NF | wc -l)"
	if [ "$num_dupes" -gt "$max_dupes" ]
	then
		warn "Warning: there are $_color_RED$num_dupes$_color_yellow duplicated lines in"
		warn "         the file $filename"
	fi
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
	# Using bash eval to check the zshrc plugin list
	# is technically not correct.
	# But it does the job to detect most of the student
	# fckups. For example parenthesis missplacement.
	if ! eval "$plugin_list" &> /dev/null;
	then
		warn "Warning: there might be a syntax error in the ${_color_WHITE}plugins=()$_color_yellow list"
		warn "         please have a look at the $_color_RED$HOME/.zshrc$_color_yellow file"
		warn "         in line $_color_RED$plugin_list_line"
	fi
}

function check_zshrc_contents() {
	[[ -f ~/.zshrc ]] || return

	assert_num_file_lines ~/.zshrc 60 110
	assert_num_dupe_lines ~/.zshrc 6
	check_zshrc_plugins
}

function check_zprofile_contents() {
	[[ -f ~/.zprofile ]] || return

	assert_num_file_lines ~/.zprofile 3 15
	assert_num_dupe_lines ~/.zprofile 5
}

function main() {
	check_colors
	device_info
	check_basics
	if is_mac
	then
		check_brew
		check_sip_mac
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
		check_github_org_invite_accept
		check_git_and_github_email_match
	fi
	check_zshrc_contents
	check_zprofile_contents
	if is_web
	then
		check_ruby
		check_database
		check_ready_commit_email
	elif is_data
	then
		check_docker
	fi
	if [ "$num_errors" == "0" ] && [ "$num_warnings" == "0" ]
	then
		log "✅$_color_GREEN your system is healthy"
	else
		log "Summary warnings: $num_warnings errors: $num_errors"
	fi
}

main

