revert_suid() {
	usage_revert_suid() {
		echo "Usage: ./panix.sh --revert suid"
		echo "Reverts any changes made by the setup_suid_backdoor module."
	}

	# Ensure the function is run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Define the default binaries that had SUID bits set
	default_binaries=("find" "dash" "python" "python3")

	# Function to remove SUID bit from a binary
	remove_suid_bit() {
		local binary_path="$1"
		if [[ -f "$binary_path" ]]; then
			chmod u-s "$binary_path"
			if [[ $? -eq 0 ]]; then
				echo "[+] Removed SUID bit from $binary_path"
			else
				echo "[-] Failed to remove SUID bit from $binary_path"
			fi
		else
			echo "[-] Binary not found: $binary_path. Skipping."
		fi
	}

	# Function to revert SUID for default binaries
	revert_default_suid() {
		echo "[+] Reverting SUID bits on default binaries..."

		for bin in "${default_binaries[@]}"; do
			if command -v "$bin" &> /dev/null; then
				bin_path=$(command -v "$bin")
				# Resolve symbolic links to get the real path
				real_bin_path=$(realpath "$bin_path")
				remove_suid_bit "$real_bin_path"
			else
				echo "[-] Binary '$bin' not found on the system. Skipping."
			fi
		done
	}

	# Revert default SUID bits
	revert_default_suid

	return 0
}
