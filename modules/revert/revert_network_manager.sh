revert_network_manager() {
	usage_revert_network_manager() {
		echo "Usage: ./panix.sh --revert network-manager"
		echo "Reverts any changes made by the setup_network-manager module."
	}
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local dispatcher_file="/etc/NetworkManager/dispatcher.d/01-ifupdown"
	local custom_file="/etc/NetworkManager/dispatcher.d/panix-dispatcher.sh"

	# Function to remove payload from dispatcher file
	remove_payload() {
		local file="$1"
		if [[ -f "$file" ]]; then
			echo "[+] Checking for payload in $file..."

			if ! grep -q "bash -i >& " "$file" && ! grep -q "nohup setsid bash -c" "$file"; then
				echo "[+] No payload found in $file."
			else
				echo "[!] Payload found in $file. Removing..."
				sed -i '/bash -i >& /d' "$file"
				sed -i '/nohup setsid bash -c/d' "$file"
				echo "[+] Payload removed from $file."
			fi
		else
			echo "[-] File not found: $file"
		fi
	}

	# Remove payload from dispatcher files
	if [[ -f "$dispatcher_file" ]]; then
		remove_payload "$dispatcher_file"
	fi

	if [[ -f "$custom_file" ]]; then
		echo "[+] Removing custom dispatcher file: $custom_file..."
		rm -f "$custom_file"
		echo "[+] Custom dispatcher file removed."
	fi

	echo "[+] NetworkManager persistence reverted."
	return 0
}
