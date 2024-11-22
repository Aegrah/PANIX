revert_ld_preload() {
	usage_revert_ld_preload() {
		echo "Usage: ./panix.sh --revert ld-preload"
		echo "Reverts any changes made by the setup_ld_preload module."
	}

	# Ensure the function is executed as root
	if [[ $UID -ne 0 ]]; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local preload_compile_dir="/tmp/preload"
	local preload_name="preload_backdoor"
	local preload_source="${preload_compile_dir}/${preload_name}.c"
	local preload_lib="/lib/${preload_name}.so"
	local preload_file="/etc/ld.so.preload"

	# Remove the shared library path from /etc/ld.so.preload
	if [[ -f "$preload_file" ]]; then
		if grep -q "$preload_lib" "$preload_file"; then
			echo "[+] Removing $preload_lib from $preload_file..."
			sed -i "\|$preload_lib|d" "$preload_file"
			echo "[+] Removed entry from $preload_file."
		else
			echo "[-] $preload_lib not found in $preload_file."
		fi
	else
		echo "[-] $preload_file does not exist."
	fi

	# Remove the malicious shared library
	if [[ -f "$preload_lib" ]]; then
		echo "[+] Removing malicious shared library $preload_lib..."
		rm -f "$preload_lib"
		echo "[+] Removed $preload_lib."
	else
		echo "[-] Malicious shared library $preload_lib not found."
	fi

	# Clean up the compile directory
	if [[ -d "$preload_compile_dir" ]]; then
		echo "[+] Removing temporary directory $preload_compile_dir..."
		rm -rf "$preload_compile_dir"
		echo "[+] Removed $preload_compile_dir."
	else
		echo "[-] Temporary directory $preload_compile_dir not found."
	fi

	echo "[!] Note: The backdoor may still be active in your current session."
	echo "[!] Please restart your shell session to fully disable the backdoor."
	echo "[!] Run 'exec bash' to start a new shell session."

	return 0
}
