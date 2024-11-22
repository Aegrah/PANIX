revert_cap() {
	usage_revert_cap() {
		echo "Usage: ./panix.sh --revert cap"
		echo "Reverts any changes made by the setup_cap_backdoor module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Function to escape special characters in sed patterns
	escape_sed_pattern() {
		local pattern="$1"
		# Escape |, \, /, and & characters
		printf '%s' "$pattern" | sed 's/[|\\/&]/\\&/g'
	}

	# Function to verify if a file is a regular file
	is_regular_file() {
		local file="$1"
		if [[ -f "$file" ]]; then
			return 0
		else
			return 1
		fi
	}

	# Ensure setcap is found
	if ! command -v setcap &>/dev/null; then
		if [[ -x /sbin/setcap ]]; then
			SETCAP="/sbin/setcap"
		else
			echo "[-] setcap not found. Ensure the 'libcap2-bin' package is installed."
			return 1
		fi
	else
		SETCAP=$(command -v setcap)
	fi

	# List of default binaries modified by setup_cap_backdoor
	local binaries=("perl" "ruby" "php" "python" "python3" "node")

	for bin in "${binaries[@]}"; do
		if command -v "$bin" &> /dev/null; then
			local path
			path=$(command -v "$bin") || { echo "[-] Failed to find path for $bin"; continue; }

			# Resolve symbolic links to get the real path
			if command -v realpath &>/dev/null; then
				path=$(realpath "$path") || { echo "[-] Failed to resolve realpath for $bin"; continue; }
			elif command -v readlink &>/dev/null; then
				path=$(readlink -f "$path") || { echo "[-] Failed to resolve readlink for $bin"; continue; }
			else
				echo "[-] Neither realpath nor readlink is available to resolve $bin path."
				continue
			fi

			# Check if path is a regular file
			if is_regular_file "$path"; then
				# Check if the file has any capabilities set
				if getcap "$path" &>/dev/null; then
					# Remove capabilities from the binary
					$SETCAP -r "$path"
					if [[ $? -eq 0 ]]; then
						echo "[+] Removed capabilities from $path"
					else
						echo "[-] Failed to remove capabilities from $path"
					fi
				else
					echo "[-] No capabilities set on $path. Skipping."
				fi
			else
				echo "[-] $path is not a regular file. Skipping."
			fi
		else
			echo "[-] $bin is not present on the system."
		fi
	done

	return 0
}
