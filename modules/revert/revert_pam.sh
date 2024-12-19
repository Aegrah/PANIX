revert_pam() {
	usage_revert_pam() {
		echo "Usage: ./panix.sh --revert pam"
		echo "Reverts any changes made by the setup_pam_persistence module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	remove_rogue_pam() {
		echo "[+] Searching for rogue PAM module"
		# Check for the presence of the malicious PAM module
		pam_module_paths=(
			"/lib/security/pam_unix.so"
			"/usr/lib/security/pam_unix.so"
			"/usr/lib64/security/pam_unix.so"
			"/lib/x86_64-linux-gnu/security/pam_unix.so"
			"/usr/lib/x86_64-linux-gnu/security/pam_unix.so"
			"/lib64/security/pam_unix.so"
		)
		
		# Revert pam_unix.so with the pam_unix.so.bak backup 
		for pam_module in "${pam_module_paths[@]}"; do
			if [[ -f "$pam_module.bak" ]]; then
				mv -f "$pam_module.bak" "$pam_module"
				if [[ $? -eq 0 ]]; then
					echo "[+] Restored original PAM module '$pam_module'."
				else
					echo "[-] Failed to restore original PAM module '$pam_module'."
				fi
			fi
		done
	}

	# Function to remove malicious PAM_EXEC configurations and scripts
	remove_pam_exec_backdoor() {
		echo "[+] Removing PAM_EXEC backdoor..."

		# Remove the reverse shell script
		if [[ -f "/bin/pam_exec_backdoor.sh" ]]; then
			rm -f "/bin/pam_exec_backdoor.sh"
			if [[ $? -eq 0 ]]; then
				echo "[+] Removed '/bin/pam_exec_backdoor.sh'."
			else
				echo "[-] Failed to remove '/bin/pam_exec_backdoor.sh'."
			fi
		else
			echo "[-] '/bin/pam_exec_backdoor.sh' not found."
		fi

		# Remove the PAM_EXEC line from /etc/pam.d/sshd
		pam_sshd_file="/etc/pam.d/sshd"
		pam_line="session    optional     pam_exec.so seteuid /bin/pam_exec_backdoor.sh"
		if grep -Fxq "$pam_line" "$pam_sshd_file"; then
			sed -i "\|$pam_line|d" "$pam_sshd_file"
			echo "[+] Removed PAM_EXEC line from '$pam_sshd_file'."
		else
			echo "[-] PAM_EXEC line not found in '$pam_sshd_file'."
		fi

		# Restart SSH service
		echo "[+] Restarting SSH service..."
		if systemctl restart sshd; then
			echo "[+] SSH service restarted successfully."
		else
			echo "[-] Failed to restart SSH service."
		fi
	}

	# Function to remove PAM_EXEC logging backdoor
	remove_pam_exec_logging() {
		echo "[+] Removing PAM_EXEC logging backdoor..."

		# Remove the spy script
		if [[ -f "/var/log/spy.sh" ]]; then
			rm -f "/var/log/spy.sh"
			if [[ $? -eq 0 ]]; then
				echo "[+] Removed '/var/log/spy.sh'."
			else
				echo "[-] Failed to remove '/var/log/spy.sh'."
			fi
		else
			echo "[-] '/var/log/spy.sh' not found."
		fi

		# Remove the log file
		if [[ -f "/var/log/panix.log" ]]; then
			rm -f "/var/log/panix.log"
			if [[ $? -eq 0 ]]; then
				echo "[+] Removed '/var/log/panix.log'."
			else
				echo "[-] Failed to remove '/var/log/panix.log'."
			fi
		else
			echo "[-] '/var/log/panix.log' not found."
		fi

		# Remove the PAM_EXEC line from /etc/pam.d/common-auth
		pam_common_auth_file="/etc/pam.d/common-auth"
		pam_sshd_file_rhel="/etc/pam.d/sshd"
		pam_line='auth optional pam_exec.so quiet expose_authtok /var/log/spy.sh'
		if grep -Fxq "$pam_line" "$pam_common_auth_file"; then
			sed -i "\|$pam_line|d" "$pam_common_auth_file"
			echo "[+] Removed PAM_EXEC line from '$pam_common_auth_file'."
		elif grep -Fxq "$pam_line" "$pam_sshd_file_rhel"; then
			sed -i "\|$pam_line|d" "$pam_sshd_file_rhel"
			echo "[+] Removed PAM_EXEC line from '$pam_sshd_file_rhel'."
		else
			echo "[-] PAM_EXEC line not found in '$pam_common_auth_file'."
		fi
	}

	# Remove PAM_EXEC backdoor and logging
	remove_rogue_pam
	remove_pam_exec_backdoor
	remove_pam_exec_logging

	# Restore SELinux enforcing mode if it was disabled
	if command -v sestatus &>/dev/null && sestatus | grep -q "disabled"; then
		echo "[+] Restoring SELinux enforcing mode..."
		setenforce 1
		echo "[+] SELinux enforcing mode restored."
	fi

	return 0
}
