# Function to revert initramfs changes
revert_initramfs() {
	usage_revert_initramfs() {
		echo "Usage: sudo ./panix.sh --revert initramfs"
		echo "This reverts changes made by the initramfs persistence module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# 1. Restore the original initramfs backup (if it exists)
	local initrd="/boot/initrd.img-$(uname -r)"
	local initrd_backup="${initrd}.bak"

	if [[ -f "$initrd_backup" ]]; then
		echo "[!] Restoring initramfs from backup: $initrd_backup..."
		cp "$initrd_backup" "$initrd"
		if [[ $? -ne 0 ]]; then
			echo "Error: Failed to restore initramfs from backup."
			return 1
		fi
		echo "[+] Initramfs restored successfully."
	else
		echo "[-] No backup initramfs found at $initrd_backup. Skipping restore."
	fi

	# 2. Remove the custom dracut module directory (if it exists)
	local dracut_dir="/usr/lib/dracut/modules.d/99panix"
	if [[ -d "$dracut_dir" ]]; then
		echo "[!] Removing custom dracut module directory: $dracut_dir..."
		rm -rf "$dracut_dir"
		if [[ $? -ne 0 ]]; then
			echo "Error: Failed to remove dracut module directory."
			return 1
		fi
		echo "[+] Custom dracut module directory removed."
	else
		echo "[-] Custom dracut module directory not found: $dracut_dir"
	fi

	# 3. Rebuild the initramfs using dracut or update-initramfs
	if command -v dracut &>/dev/null; then
		echo "[!] Rebuilding initramfs using dracut..."
		dracut --force "$initrd" "$(uname -r)"
		if [[ $? -ne 0 ]]; then
			echo "Error: dracut failed to rebuild initramfs."
			return 1
		fi
		echo "[+] Initramfs rebuilt successfully with dracut."
	elif command -v update-initramfs &>/dev/null; then
		echo "[!] Rebuilding initramfs using update-initramfs..."
		update-initramfs -u -k "$(uname -r)"
		if [[ $? -ne 0 ]]; then
			echo "Error: update-initramfs failed to rebuild initramfs."
			return 1
		fi
		echo "[+] Initramfs rebuilt successfully with update-initramfs."
	else
		echo "Warning: Neither dracut nor update-initramfs is installed. Skipping initramfs rebuild."
	fi

	# 4. Clean up temporary files (if applicable)
	local tmp_dir="/tmp/initramfs*"
	echo "[!] Cleaning up temporary files..."
	rm -rf $tmp_dir
	if [[ $? -ne 0 ]]; then
		echo "Error: Failed to clean up temporary files."
		return 1
	fi
	echo "[+] Temporary files cleaned up."

	echo "[+] Initramfs persistence reverted successfully."
	return 0
}
