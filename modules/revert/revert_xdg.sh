revert_xdg() {
	usage_revert_xdg() {
		echo "Usage: ./panix.sh --revert xdg"
		echo "Reverts any changes made by the setup_xdg module."
	}

	# Determine if the script is run as root
	if [[ "$(id -u)" -eq 0 ]]; then
		is_root=true
	else
		is_root=false
	fi

	# Function to display usage if needed
	if [[ "$1" == "--help" || "$1" == "-h" ]]; then
		usage_revert_xdg_backdoor
		return 0
	fi

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

	# Function to determine xdg directory based on user privileges
	determine_xdg_dir() {
		local user="$1"
		if [[ "$user" == "root" ]]; then
			echo "/etc/xdg/autostart/"
		else
			echo "/home/$user/.config/autostart/"
		fi
	}

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

	# Function to remove the XDG backdoor desktop entry and associated command script
	remove_xdg_backdoor() {
		local user="$1"
		local xdg_dir=$(determine_xdg_dir "$user")
		local desktop_entry=""
		local command_script=""

		echo "[+] Reverting XDG backdoor for user '$user' at: $xdg_dir"

		# Remove default desktop entries and scripts
		if [[ "$is_root" == true && "$user" == "root" ]]; then
			desktop_entry="/etc/xdg/autostart/pkc12-register.desktop"
			command_script="/etc/xdg/pkc12-register"
		elif [[ "$is_root" == false && "$user" != "root" ]]; then
			desktop_entry="/home/$user/.config/autostart/user-dirs.desktop"
			command_script="/home/$user/.config/autostart/.user-dirs"
		fi

		# Remove default desktop entry and script
		if [[ -n "$desktop_entry" ]]; then
			if [[ -f "$desktop_entry" ]]; then
				backup_file "$desktop_entry"
				rm -f "$desktop_entry"
				if [[ $? -eq 0 ]]; then
					echo "[+] Removed desktop entry: $desktop_entry"
				else
					echo "[-] Failed to remove desktop entry: $desktop_entry"
				fi
			else
				echo "[-] Desktop entry not found: $desktop_entry. Skipping."
			fi
		fi

		if [[ -n "$command_script" ]]; then
			if [[ -f "$command_script" ]]; then
				backup_file "$command_script"
				rm -f "$command_script"
				if [[ $? -eq 0 ]]; then
					echo "[+] Removed command script: $command_script"
				else
					echo "[-] Failed to remove command script: $command_script"
				fi
			else
				echo "[-] Command script not found: $command_script. Skipping."
			fi
		fi

		# Scan for any custom desktop entries that match the malicious pattern
		echo "[+] Scanning for custom XDG backdoors in $xdg_dir"
		for desktop_file in "$xdg_dir"*.desktop; do
			if [[ -f "$desktop_file" ]]; then
				# Extract the Exec line
				exec_line=$(grep -E "^Exec=" "$desktop_file" | cut -d'=' -f2-)
				# Check if the Exec line contains the malicious command pattern
				if echo "$exec_line" | grep -q "sh -i >& /dev/tcp/"; then
					echo "[+] Identified malicious desktop entry: $desktop_file"
					backup_file "$desktop_file"
					rm -f "$desktop_file"
					if [[ $? -eq 0 ]]; then
						echo "[+] Removed malicious desktop entry: $desktop_file"
					else
						echo "[-] Failed to remove malicious desktop entry: $desktop_file"
					fi

					# Extract the command script path from Exec line
					# Assuming Exec points to the command script directly
					command_script_path="$exec_line"
					if [[ -f "$command_script_path" ]]; then
						backup_file "$command_script_path"
						rm -f "$command_script_path"
						if [[ $? -eq 0 ]]; then
							echo "[+] Removed malicious command script: $command_script_path"
						else
							echo "[-] Failed to remove malicious command script: $command_script_path"
						fi
					else
						echo "[-] Command script not found: $command_script_path. Skipping."
					fi
				else
					echo "[-] No malicious pattern found in Exec line of: $desktop_file. Skipping."
				fi
			fi
		done
	}

	# Function to revert backdoors for a single user
	revert_user_xdg_backdoor() {
		local user="$1"
		remove_xdg_backdoor "$user"
	}

	# Main revert logic based on execution context
	if [[ "$is_root" == true ]]; then
		echo "[+] Running as root. Reverting XDG backdoors for root and all non-system users."

		# Revert XDG backdoor for root
		revert_user_xdg_backdoor "root"

		# Iterate over all user directories in /home
		for user_home in /home/*; do
			if [[ -d "$user_home" ]]; then
				user_name=$(basename "$user_home")
				if is_system_user "$user_name"; then
					echo "[-] Skipping system user '$user_name'."
					continue
				fi
				revert_user_xdg_backdoor "$user_name"
			fi
		done
	else
		# Non-root execution: revert XDG backdoor for the current user only
		current_user=$(whoami)
		echo "[+] Running as non-root. Reverting XDG backdoor for user '$current_user'."

		revert_user_xdg_backdoor "$current_user"
	fi

	return 0
}
