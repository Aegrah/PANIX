revert_rootkit() {
	usage_revert_rootkit() {
		echo "Usage: ./panix.sh --revert rootkit"
		echo "Reverts any changes made by the setup_rootkit module."
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

	# Function to remove a directory if it exists
	remove_directory() {
		local dir_path="$1"
		if [[ -d "$dir_path" ]]; then
			rm -rf "$dir_path"
			echo "[+] Removed directory: $dir_path"
		else
			echo "[-] Directory not found: $dir_path"
		fi
	}

	# Function to send kill -63 0 to unload the module
	unload_module_signal() {
		echo "[+] Sending 'kill -63 0' to unload the rootkit module..."
		kill -63 0
		if [[ $? -ne 0 ]]; then
			echo "[-] Failed to send signal to unload the rootkit module."
			echo "You may need to unload it manually."
		else
			echo "[+] Signal sent successfully."
		fi
	}

	# Function to unload a kernel module
	unload_kernel_module() {
		local module_name="$1"
		if lsmod | grep -q "^${module_name}\b"; then
			echo "[+] Unloading kernel module: $module_name"
			rmmod -f "$module_name"
			if [[ $? -eq 0 ]]; then
				echo "[+] Kernel module '$module_name' unloaded successfully."
			else
				echo "[-] Failed to unload kernel module '$module_name'."
			fi
		else
			echo "[-] Kernel module '$module_name' is not loaded."
		fi
	}

	rk_path="/dev/shm/.rk"
	if [[ -d "$rk_path" ]]; then

		# Step 1: Send kill -63 0 signal to prepare unloading
		unload_module_signal

		# Step 2: Identify and unload kernel modules
		echo "[+] Identifying loaded rootkit kernel modules in $rk_path..."

		# Find all .ko files in rk_path
		ko_files=("$rk_path"/*.ko)

		if [[ ! -e "${ko_files[0]}" ]]; then
			echo "[-] No .ko files found in $rk_path."
		else
			for ko_file in "${ko_files[@]}"; do
				module_name=$(basename "$ko_file" .ko)
				unload_kernel_module "$module_name"
			done
		fi
	else
		echo "[-] Rootkit directory '$rk_path' not found. Skipping module unloading."
	fi

	# Step 3: Remove kernel module files
	if [[ -d "$rk_path" ]]; then
		echo "[+] Removing kernel module files from $rk_path..."
		for ko_file in "$rk_path"/*.ko; do
			if [[ -f "$ko_file" ]]; then
				remove_file "$ko_file"
			fi
		done
	fi

	# Step 4: Remove /dev/shm/.rk directory
	remove_directory "$rk_path"

	# Step 5: Remove downloaded files in /tmp
	echo "[+] Removing downloaded files in /tmp..."
	remove_directory "/tmp/diamorphine"
	remove_file "/tmp/diamorphine.zip"
	remove_file "/tmp/diamorphine.tar"
	remove_directory "/tmp/Diamorphine.git"

	# Step 6: Reload kernel modules to ensure no remnants remain
	echo "[+] Reloading kernel modules..."
	depmod -a
	if [[ $? -eq 0 ]]; then
		echo "[+] Kernel modules reloaded successfully."
	else
		echo "[-] Failed to reload kernel modules."
	fi

	return 0
}
