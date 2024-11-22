revert_motd() {
	usage_revert_motd() {
		echo "Usage: ./panix.sh --revert motd"
		echo "Reverts any changes made by the setup_motd_backdoor module."
	}

	# Ensure the function is run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Function to remove a file if it exists
	remove_file() {
		local file_path="$1"
		if [[ -f "$file_path" ]]; then
			rm -f "$file_path"
			echo "[+] Removed file: $file_path"
		else
			echo "[-] File not found: $file_path"
		fi
	}

	# Function to remove a MOTD backdoor script if it contains malicious commands
	remove_motd_script() {
		local script_path="$1"
		# Define patterns that indicate a reverse shell
		local patterns=("bash -i >& /dev/tcp" "nohup setsid /bin/sh " "bash -c 'sh -i" "setsid nohup")
		
		for pattern in "${patterns[@]}"; do
			if grep -q "$pattern" "$script_path"; then
				echo "[+] Identified malicious MOTD script: $script_path"
				remove_file "$script_path"
				return
			fi
		done
	}

	# Remove default MOTD backdoor script
	default_motd_path="/etc/update-motd.d/137-python-upgrades"
	echo "[+] Removing default MOTD backdoor script..."
	
	if [[ -f "$default_motd_path" ]]; then
		remove_motd_script "$default_motd_path"
	fi

	# Search and remove custom MOTD backdoor scripts
	echo "[+] Searching for custom MOTD backdoor scripts in /etc/update-motd.d/..."
	for motd_script in /etc/update-motd.d/*; do
		# Ensure it's a regular file
		if [[ ! -f "$motd_script" ]]; then
			continue
		fi

		# Exclude default scripts based on naming convention (e.g., 00-header, 10-help-text)
		script_basename=$(basename "$motd_script")
		if [[ "$script_basename" =~ ^[0-9]{2,3}- ]]; then
			# Check for malicious patterns
			remove_motd_script "$motd_script"
		fi
	done

	# Reload MOTD to apply changes
	echo "[+] Reloading MOTD rules..."
	if command -v run-parts &>/dev/null; then
		run-parts /etc/update-motd.d/ &> /dev/null
		echo "[+] MOTD rules reloaded using run-parts."
	else
		echo "[-] run-parts command not found. Skipping MOTD reload."
	fi

	return 0
}
