revert_lkm() {
	usage_revert_lkm() {
		echo "Usage: ./panix.sh --revert lkm"
		echo "Reverts any changes made by the setup_lkm_backdoor module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local lkm_name="panix"
	local lkm_compile_dir="/tmp/lkm"
	local lkm_destination="/lib/modules/$(uname -r)/kernel/drivers/${lkm_name}.ko"
	local lkm_module_name="${lkm_name}"

	# Unload the kernel module if it is loaded
	if lsmod | grep -q "^${lkm_module_name} "; then
		echo "[+] Unloading kernel module '${lkm_module_name}'..."
		rmmod "${lkm_module_name}"
		if [[ $? -eq 0 ]]; then
			echo "[+] Kernel module '${lkm_module_name}' unloaded successfully."
		else
			echo "[-] Failed to unload kernel module '${lkm_module_name}'."
		fi
	else
		echo "[-] Kernel module '${lkm_module_name}' is not loaded."
	fi

	# Remove the kernel module file
	if [[ -f "${lkm_destination}" ]]; then
		echo "[+] Removing kernel module file '${lkm_destination}'..."
		rm -f "${lkm_destination}"
		if [[ $? -eq 0 ]]; then
			echo "[+] Kernel module file '${lkm_destination}' removed successfully."
		else
			echo "[-] Failed to remove kernel module file '${lkm_destination}'."
		fi
	else
		echo "[-] Kernel module file '${lkm_destination}' not found."
	fi

	# Clean up the compile directory
	if [[ -d "${lkm_compile_dir}" ]]; then
		echo "[+] Removing temporary directory '${lkm_compile_dir}'..."
		rm -rf "${lkm_compile_dir}"
		if [[ $? -eq 0 ]]; then
			echo "[+] Temporary directory '${lkm_compile_dir}' removed successfully."
		else
			echo "[-] Failed to remove temporary directory '${lkm_compile_dir}'."
		fi
	else
		echo "[-] Temporary directory '${lkm_compile_dir}' not found."
	fi

	# Remove panix from /etc/modules, /etc/modules-load.d/panix.conf and /usr/lib/modules-load.d/panix.conf
	echo "[+] Removing panix from /etc/modules, /etc/modules-load.d/ and /usr/lib/modules-load.d/..."
	sed -i '/panix/d' /etc/modules
	rm -f /etc/modules-load.d/panix.conf
	rm -f /usr/lib/modules-load.d/panix.conf

	# Update module dependencies
	echo "[+] Updating module dependencies..."
	depmod -a
	echo "[+] Module dependencies updated."

	return 0
}
