revert_authorized_keys() {
	local path=""

	usage_revert_authorized_keys() {
		echo "Usage: ./panix.sh --revert authorized-keys"
		echo "Reverts any changes made by the setup_authorized_keys module."
	}

	if check_root; then
		path="/root/.ssh/authorized_keys"
	else
		local current_user=$(whoami)
		path="/home/$current_user/.ssh/authorized_keys"
	fi

	if [[ -f "${path}.bak" ]]; then
		echo "[+] Restoring backup from ${path}.bak to $path."
		mv "${path}.bak" "$path"
		chmod 600 "$path"
		echo "[+] Revert complete: Restored $path from backup."
		return 1
	else
		echo "[-] Backup file ${path}.bak not found. No changes made."
		return 0
	fi

	return 0
}
