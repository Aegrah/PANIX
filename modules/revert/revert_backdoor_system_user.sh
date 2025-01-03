revert_backdoor_system_user() {
	usage_revert_backdoor_system_user() {
		echo "Usage: ./panix.sh --revert backdoor-system-user"
		echo "Reverts any changes made by the setup_backdoor_system_user module for the default option."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Define users to check
	# Add custom users here if you want to revert them
	local users=("news" "nobody")

	for user in "${users[@]}"; do
		# Check if user exists in /etc/passwd
		user_entry=$(grep "^$user:" /etc/passwd)
		if [[ -n "$user_entry" ]]; then
			# Extract home directory
			home_dir=$(echo "$user_entry" | cut -d: -f6)

			if [[ -d "$home_dir/.ssh" ]]; then
				# Remove the .ssh directory
				echo "[+] Removing .ssh directory for user: $user"
				rm -rf "$home_dir/.ssh"
				if [[ $? -eq 0 ]]; then
					echo "[+] Successfully removed .ssh directory for $user."
				else
					echo "[-] Failed to remove .ssh directory for $user."
				fi
			else
				echo "[+] No .ssh directory found for $user."
			fi

			# Restore /etc/passwd entry for the user
			echo "[+] Checking /etc/passwd entry for user: $user"
			if grep -q ":$home_dir:/usr/sbin/nologin " /etc/passwd; then
				echo "[+] Reverting /etc/passwd entry for user: $user"
				sed -i "s|:$home_dir:/usr/sbin/nologin |:$home_dir:/usr/sbin/nologin|" /etc/passwd
				if [[ $? -eq 0 ]]; then
					echo "[+] Successfully reverted /etc/passwd entry for $user."
				else
					echo "[-] Failed to revert /etc/passwd entry for $user."
				fi
			else
				echo "[+] No modifications found for /etc/passwd entry of user: $user. Skipping."
			fi
		fi
	done

	# Remove '/usr/sbin/nologin ' if it exists
	if [[ -f "/usr/sbin/nologin " ]]; then
		echo "[+] Removing '/usr/sbin/nologin '"
		rm -f "/usr/sbin/nologin "
		if [[ $? -eq 0 ]]; then
			echo "[+] Successfully removed '/usr/sbin/nologin '."
		else
			echo "[-] Failed to remove '/usr/sbin/nologin '."
		fi
	else
		echo "[+] '/usr/sbin/nologin ' not found. Skipping."
	fi

	# Revert changes to /etc/shells
	if grep -q "nologin " /etc/shells; then
		echo "[+] Reverting /etc/shells to remove 'nologin ' entry."
		sed -i '/nologin /d' /etc/shells
		if [[ $? -eq 0 ]]; then
			echo "[+] Successfully removed 'nologin ' from /etc/shells."
		else
			echo "[-] Failed to revert changes in /etc/shells."
		fi
	else
		echo "[+] 'nologin ' not found in /etc/shells. Skipping."
	fi

	return 0
}
