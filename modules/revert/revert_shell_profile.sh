revert_shell_profile() {
	usage_revert_shell_profile() {
		echo "Usage: ./panix.sh --revert shell-profile"
		echo "Reverts any changes made by the setup_shell_profile module."
	}

	# Determine if the script is run as root
	if [[ "$(id -u)" -eq 0 ]]; then
		is_root=true
	else
		is_root=false
	fi

	# Function to backup a file if not already backed up
	backup_file() {
		local file_path="$1"
		if [[ -f "$file_path" && ! -f "${file_path}.backup" ]]; then
			cp "$file_path" "${file_path}.backup"
			echo "[+] Backup of $file_path created at ${file_path}.backup"
		elif [[ -f "$file_path" && -f "${file_path}.backup" ]]; then
			echo "[+] Backup of $file_path already exists at ${file_path}.backup"
		else
			echo "[-] File not found: $file_path. Skipping backup."
		fi
	}

	remove_lines_matching_pattern() {
		local pattern="$1"
		local file="$2"

		# Use '|' as the delimiter in sed to avoid conflict with '/'
		if grep -q "$pattern" "$file"; then
			sed -i "\|$pattern|d" "$file"
			echo "[+] Removed lines matching pattern: '$pattern' from $file"
		fi
	}

	# Define shell profile files to check
	system_shell_profiles=(
		"/etc/profile"
		"/etc/bash.bashrc"
		"/etc/zsh/zshrc"
		"/etc/profile.d/*.sh"
	)

	user_shell_profiles=(
		"$HOME/.bash_profile"
		"$HOME/.bashrc"
		"$HOME/.profile"
		"$HOME/.zshrc"
	)

	# Define malicious patterns indicative of a reverse shell
	malicious_patterns=(
		"nohup bash -i > /dev/tcp/"
		"setsid nohup bash -c 'bash -i >& /dev/tcp/"
		"bash -i >& /dev/tcp/"
		"bash -c 'sh -i >& /dev/tcp/"
		"bash -i > /dev/tcp/"
		"sh -i >& /dev/udp/"
		"bash -c 'bash -i >& /dev/tcp/"
		"bash -c 'sh -i >& /dev/udp/"
		"nohup setsid bash -c 'sh -i >& /dev/tcp/"
		"nohup setsid sh -c 'sh -i >& /dev/tcp/"
		"nohup setsid"
	)

	# Define system users to skip (modify this array if certain users should not be processed)
	system_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "cups-pk-helper" "dnsmasq-dhcp" "sshd" "polkitd")

	# Function to check if a user is a system user
	is_system_user() {
		local user="$1"
		for sys_user in "${system_users[@]}"; do
			if [[ "$user" == "$sys_user" ]]; then
				return 0
			fi
		done
		return 1
	}

	# Function to process a single user's shell profiles
	process_user_shell_profiles() {
		local user_home="$1"
		local user_name="$2"

		echo "[+] Processing shell profiles for user '$user_name' at: $user_home"

		for profile in "${user_shell_profiles[@]}"; do
			# Replace $HOME with the actual user home directory
			local expanded_profile="${profile/#\$HOME/$user_home}"

			if [[ -f "$expanded_profile" ]]; then
				backup_file "$expanded_profile"
				for pattern in "${malicious_patterns[@]}"; do
					remove_lines_matching_pattern "$pattern" "$expanded_profile"
				done
			else
				echo "[-] Shell profile file not found: $expanded_profile. Skipping."
			fi
		done
	}

	# Function to process system-wide shell profiles
	process_system_shell_profiles() {
		echo "[+] Processing system-wide shell profiles."

		for profile in "${system_shell_profiles[@]}"; do
			# Handle wildcard profiles like /etc/profile.d/*.sh
			if [[ "$profile" == *.sh ]]; then
				for script in $profile; do
					if [[ -f "$script" ]]; then
						backup_file "$script"
						for pattern in "${malicious_patterns[@]}"; do
							remove_lines_matching_pattern "$pattern" "$script"
						done
					fi
				done
				continue
			fi

			if [[ -f "$profile" ]]; then
				echo "[+] Processing shell profile file: $profile"
				backup_file "$profile"
				for pattern in "${malicious_patterns[@]}"; do
					remove_lines_matching_pattern "$pattern" "$profile"
				done
			else
				echo "[-] Shell profile file not found: $profile. Skipping."
			fi
		done
	}

	# Main logic based on execution context
	if [[ "$is_root" == true ]]; then
		echo "[+] Running as root. Reverting shell profiles for root and all non-system users."

		# Revert system-wide shell profiles
		process_system_shell_profiles

		# Iterate over all user directories in /home
		for user_home in /home/*; do
			if [[ -d "$user_home" ]]; then
				user_name=$(basename "$user_home")
				if is_system_user "$user_name"; then
					echo "[-] Skipping system user '$user_name'."
					continue
				fi
				process_user_shell_profiles "$user_home" "$user_name"
			fi
		done
	else
		# Non-root execution: revert shell profiles for the current user only
		current_user=$(whoami)
		user_home=$(eval echo "~$current_user")
		echo "[+] Running as non-root. Reverting shell profiles for user '$current_user' at: $user_home"

		process_user_shell_profiles "$user_home" "$current_user"
	fi

	echo "[+] Shell profiles reverted successfully."
	echo "[!] Restart your shell sessions to apply changes."
	echo "[!] Run 'source /etc/profile' to apply changes system-wide (if applicable)."
	echo "[!] Run 'source ~/.bash_profile' or 'source ~/.bashrc' to apply changes to your user session."
	echo "[!] Run 'exec bash' or 'exec zsh' to restart the current shell session."

	return 0
}
