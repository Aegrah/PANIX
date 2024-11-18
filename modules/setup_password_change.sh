setup_password_change() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_password_change() {
		echo "Usage: ./panix.sh --password-change [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the new password"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --password-change --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_password_change
				exit 0
				;;
			* )
				echo "Invalid option for --password-change: $1"
				echo "Try './panix.sh --password-change --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './panix.sh --password-change --help' for more information."
		exit 1
	fi

	echo "$username:$password" | chpasswd

	if [[ $? -eq 0 ]]; then
		echo "[+] Password for user $username has been changed."
	else
		echo "[-] Failed to change password for user $username."
		exit 1
	fi
}
