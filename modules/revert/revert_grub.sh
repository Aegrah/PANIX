revert_grub() {
	usage_revert_grub() {
		echo "Usage: ./panix.sh --revert grub"
		echo "Reverts the GRUB persistence changes introduced by the module on Ubuntu/Debian."
	}

	# Must be run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	echo "[*] Reverting GRUB persistence modifications..."

	# 1) Restore /etc/default/grub if backup exists
	if [[ -f /etc/default/grub.bak ]]; then
		echo "[*] Restoring backup of /etc/default/grub from /etc/default/grub.bak..."
		cp /etc/default/grub.bak /etc/default/grub
		if [[ $? -ne 0 ]]; then
			echo "Error: Failed to restore /etc/default/grub from backup."
			return 1
		fi
		echo "[+] /etc/default/grub restored."
	else
		echo "[*] No backup /etc/default/grub.bak found. Skipping restore."
	fi

	# 2) Remove the /etc/grub.d/99_panix.cfg file
	local grub_custom_file="/etc/default/grub.d/99-panix.cfg"
	if [[ -f "$grub_custom_file" ]]; then
		echo "[*] Removing $grub_custom_file..."
		rm -f "$grub_custom_file"
		if [[ $? -ne 0 ]]; then
			echo "Error: Failed to remove $grub_custom_file."
			return 1
		fi
		echo "[+] $grub_custom_file removed."
	else
		echo "[*] $grub_custom_file not found; nothing to remove."
	fi

	# 3) Remove the /grub-panix.sh script
	local init_script="/grub-panix.sh"
	if [[ -f "$init_script" ]]; then
		echo "[*] Removing $init_script..."
		rm -f "$init_script"
		if [[ $? -ne 0 ]]; then
			echo "Error: Failed to remove $init_script."
			return 1
		fi
		echo "[+] $init_script removed."
	else
		echo "[*] $init_script not found; nothing to remove."
	fi

	# 4) Update GRUB (Ubuntu/Debian)
	echo "[*] Updating GRUB configuration..."
	if ! update-grub; then
		echo "Error: update-grub failed!"
		return 1
	fi
	echo "[+] GRUB configuration updated."

	echo "[+] GRUB persistence reverted successfully."
	return 0
}
