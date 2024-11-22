revert_passwd_user() {
	usage_revert_passwd_user() {
		echo "Usage: ./panix.sh --revert passwd-user"
		echo "Reverts any changes made by the setup_passwd_user module."
	}

	# Ensure the function is run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Function to backup /etc/passwd before making changes
	backup_passwd() {
		if [[ ! -f /etc/passwd.backup ]]; then
			cp /etc/passwd /etc/passwd.backup
			echo "[+] Backup of /etc/passwd created at /etc/passwd.backup."
		else
			echo "[!] Backup of /etc/passwd already exists at /etc/passwd.backup."
		fi
	}

	# Function to remove a user entry from /etc/passwd
	remove_user_entry() {
		local user="$1"
		if grep -q "^${user}:" /etc/passwd; then
			sed -i "\|^${user}:|d" /etc/passwd
			echo "[+] Removed user '$user' from /etc/passwd."
		else
			echo "[-] User '$user' not found in /etc/passwd."
		fi
	}

	# Function to check if a user is a legitimate system user
	is_system_user() {
		local user="$1"
		local system_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "cups-pk-helper" "dnsmasq-dhcp" "sshd" "polkitd")
		for sys_user in "${system_users[@]}"; do
			if [[ "$user" == "$sys_user" ]]; then
				return 0
			fi
		done
		return 1
	}

	# Backup /etc/passwd
	backup_passwd

	# Define system users for pattern matching
	system_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "cups-pk-helper" "dnsmasq-dhcp" "sshd" "polkitd")

	# Create a regex pattern for system users, set IFS locally
	system_users_pattern=$(IFS='|'; printf "%s|" "${system_users[@]}")
	system_users_pattern=${system_users_pattern%|}  # Remove trailing '|'

	# Properly escape regex special characters
	system_users_pattern=$(echo "$system_users_pattern" | sed 's/[.^$*+?()[\]{}|\/]/\\&/g')

	# Remove default setup entries: users with UID=0 and shell=/bin/bash, excluding system users
	echo "[+] Removing default setup user entries..."
	malicious_users=$(awk -F: '($3 == "0") && ($7 == "/bin/bash") {print $1}' /etc/passwd)

	if [[ -n "$malicious_users" ]]; then
		for user in $malicious_users; do
			if ! is_system_user "$user"; then
				echo "[+] Identified malicious user: '$user'"
				remove_user_entry "$user"

				# Optionally, remove the user account from the system
				if id "$user" &>/dev/null; then
					userdel -r "$user" && echo "[+] User account '$user' deleted from the system."
				else
					echo "[-] User account '$user' does not exist on the system."
				fi
			else
				echo "[-] Legitimate system user '$user' found. Skipping."
			fi
		done
	else
		echo "[-] No default setup user entries found to remove."
	fi

	# Remove custom setup entries by searching for suspicious entries
	echo "[+] Searching for custom setup passwd entries..."

	# Example pattern: usernames that are not in the system users list and have UID >= 65536
	all_users=$(awk -F: '{print $1}' /etc/passwd)

	# Iterate through all users
	for user in $all_users; do
		if [[ "$user" =~ ^($system_users_pattern)$ ]]; then
			continue  # Skip legitimate system users
		fi

		# Check if the user has UID >= 65536 and shell=/bin/bash
		user_info=$(grep "^$user:" /etc/passwd)
		uid=$(echo "$user_info" | awk -F: '{print $3}')
		shell=$(echo "$user_info" | awk -F: '{print $7}')

		if [[ "$uid" -ge 65536 && "$shell" == "/bin/bash" ]]; then
			echo "[+] Identified suspicious user: '$user'"
			remove_user_entry "$user"

			# Optionally, remove the user account from the system
			if id "$user" &>/dev/null; then
				userdel -r "$user" && echo "[+] User account '$user' deleted from the system."
			else
				echo "[-] User account '$user' does not exist on the system."
			fi
		fi
	done

	echo "[!] If any legitimate users were removed unintentionally, restore from the backup."
	echo "[!] Run 'sudo cp /etc/passwd.backup /etc/passwd' to restore the original /etc/passwd file if necessary."

	return 0
}
