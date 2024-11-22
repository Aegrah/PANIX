revert_backdoor_user() {
	usage_revert_backdoor_user() {
		echo "Usage: ./panix.sh --revert backdoor-user"
		echo "Reverts any changes made by the setup_backdoor_user module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Find users with UID 0 and not named 'root'
	backdoor_users=$(awk -F: '($3 == 0) && ($1 != "root") {print $1}' /etc/passwd)

	if [[ -z "$backdoor_users" ]]; then
		echo "[+] No backdoor users found."
		return 0
	fi

	for username in $backdoor_users; do
		echo "[+] Found backdoor user: $username"

		# Get next available UID above 1000
		next_uid=$(awk -F: 'BEGIN {max=999} ($3>=1000 && $3>max) {max=$3} END {print max+1}' /etc/passwd)

		# Backup /etc/passwd before making changes
		cp /etc/passwd /etc/passwd.bak
		echo "[+] Backup of /etc/passwd created at /etc/passwd.bak"

		# Use sed to change the UID from 0 to next available UID
		sed -i "s/^\($username:[^:]*:\)0:/\1$next_uid:/" /etc/passwd

		if [[ $? -eq 0 ]]; then
			echo "[+] Changed UID of $username to $next_uid in /etc/passwd."
		else
			echo "[-] Failed to change UID for user $username."
		fi
	done

	return 0
}
