revert_sudoers() {
	usage_revert_sudoers() {
		echo "Usage: ./panix.sh --revert sudoers"
		echo "Reverts any changes made by the setup_sudoers_backdoor module."
	}

	# Ensure the function is run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Function to backup a file if not already backed up
	backup_file() {
		local file_path="$1"
		if [[ -f "$file_path" && ! -f "${file_path}.backup" ]]; then
			cp "$file_path" "${file_path}.backup"
			echo "[+] Backup of $file_path created at ${file_path}.backup"
		elif [[ -f "$file_path" && -f "${file_path}.backup" ]]; then
			echo "[!] Backup of $file_path already exists at ${file_path}.backup"
		else
			echo "[-] File not found: $file_path. Skipping backup."
		fi
	}

	# Function to remove a sudoers backdoor file
	remove_sudoers_backdoor() {
		local sudoers_file="$1"

		if [[ -f "$sudoers_file" && "$sudoers_file" != *.backup ]]; then
			# Backup the sudoers file before removal
			backup_file "$sudoers_file"

			# Remove the sudoers backdoor
			rm -f "$sudoers_file"
			if [[ $? -eq 0 ]]; then
				echo "[+] Removed sudoers backdoor file: $sudoers_file"
			else
				echo "[-] Failed to remove sudoers backdoor file: $sudoers_file"
			fi
		else
			echo "[-] Sudoers backdoor file not found: $sudoers_file. Skipping."
		fi
	}

	# Define the sudoers backdoor pattern
	sudoers_pattern='^[a-zA-Z0-9._-]+ ALL=\(ALL\) NOPASSWD:ALL$'

	# Iterate over all files in /etc/sudoers.d/
	for sudoers_file in /etc/sudoers.d/*; do
		# Ensure it's a regular file
		if [[ -f "$sudoers_file" ]]; then
			# Check if the file contains any lines matching the sudoers backdoor pattern
			if grep -Eq "$sudoers_pattern" "$sudoers_file"; then
				echo "[+] Identified sudoers backdoor in file: $sudoers_file"
				remove_sudoers_backdoor "$sudoers_file"
			else
				echo "[-] No sudoers backdoor found in file: $sudoers_file. Skipping."
			fi
		else
			echo "[-] Not a regular file: $sudoers_file. Skipping."
		fi
	done

	return 0
}
