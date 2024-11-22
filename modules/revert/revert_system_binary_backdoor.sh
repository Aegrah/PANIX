revert_system_binary() {
	usage_revert_system_binary() {
		echo "Usage: ./panix.sh --revert system-binary"
		echo "Reverts any changes made by the setup_system_binary_backdoor module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Default binaries used in the setup function
	local default_binaries=("cat" "ls")

	# Function to restore a binary
	restore_binary() {
		local binary_name="$1"
		local binary_path
		binary_path=$(command -v "$binary_name" 2>/dev/null)

		if [[ -z "$binary_path" ]]; then
			echo "[-] Binary '$binary_name' not found in PATH."
			return
		fi

		if [[ -f "${binary_path}.original" ]]; then
			echo "[+] Restoring original binary for '$binary_name'..."
			mv -f "${binary_path}.original" "$binary_path"
			chmod +x "$binary_path"
			echo "[+] '$binary_name' restored successfully."
		else
			echo "[-] Backup for '$binary_name' not found. Skipping."
		fi
	}

	# Restore default binaries
	for bin in "${default_binaries[@]}"; do
		restore_binary "$bin"
	done

	# Check for any custom backdoored binaries
	# This assumes that any binary with a '.original' backup was backdoored
	echo "[+] Searching for custom backdoored binaries..."
	find / -type f -name "*.original" 2>/dev/null | while read -r backup_file; do
		original_file="${backup_file%.original}"
		if [[ -f "$original_file" ]]; then
			echo "[+] Restoring custom binary '$original_file'..."
			mv -f "$backup_file" "$original_file"
			chmod +x "$original_file"
			echo "[+] '$original_file' restored successfully."
		fi
	done

	return 0
}
