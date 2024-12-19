revert_malicious_package() {
	usage_revert_malicious_package() {
		echo "Usage: ./panix.sh --revert malicious-package"
		echo "Reverts any changes made by the setup_malicious_package module."
	}

	echo "[+] Reverting malicious package..."

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local mechanism=""
	local PACKAGE_NAME="panix"

	# Detect if RPM or DPKG was used
	if command -v rpm &> /dev/null && rpm -qa | grep -q "^${PACKAGE_NAME}"; then
		mechanism="rpm"
	elif command -v dpkg &> /dev/null && dpkg -l | grep -q "^ii  ${PACKAGE_NAME} "; then
		mechanism="dpkg"
	else
		echo "[-] Malicious package '${PACKAGE_NAME}' not found via RPM or DPKG. No action needed."
	fi

	if [[ "$mechanism" == "rpm" ]]; then
		echo "[+] Removing RPM package '${PACKAGE_NAME}'..."
		rpm -e --noscripts "${PACKAGE_NAME}"
		if [[ $? -eq 0 ]]; then
			echo "[+] RPM package '${PACKAGE_NAME}' removed successfully."
		else
			echo "[-] Failed to remove RPM package '${PACKAGE_NAME}'."
		fi

		# Remove the RPM file from /var/lib/rpm
		if [[ -f "/var/lib/rpm/${PACKAGE_NAME}.rpm" ]]; then
			echo "[+] Removing RPM file '/var/lib/rpm/${PACKAGE_NAME}.rpm'..."
			rm -f "/var/lib/rpm/${PACKAGE_NAME}.rpm"
			echo "[+] RPM file removed."
		else
			echo "[-] RPM file '/var/lib/rpm/${PACKAGE_NAME}.rpm' not found."
		fi

	elif [[ "$mechanism" == "dpkg" ]]; then
		echo "[+] Removing DPKG package '${PACKAGE_NAME}'..."
		dpkg --purge "${PACKAGE_NAME}"
		if [[ $? -eq 0 ]]; then
			echo "[+] DPKG package '${PACKAGE_NAME}' removed successfully."
		else
			echo "[-] Failed to remove DPKG package '${PACKAGE_NAME}'."
		fi
	fi

	# Remove the cron job added by the setup function
	echo "[+] Removing cron job associated with '${PACKAGE_NAME}'..."
	# Create a temporary file to store the current crontab
	crontab -l > /tmp/current_cron$$ 2>/dev/null
	if [[ $? -ne 0 ]]; then
		echo "[-] No crontab for user $(whoami). No action needed."
		rm -f /tmp/current_cron$$
	else
		# Remove lines containing the malicious package commands
		grep -v ".*${PACKAGE_NAME}.*" /tmp/current_cron$$ > /tmp/new_cron$$
		# Install the new crontab
		crontab /tmp/new_cron$$
		echo "[+] Cron job removed."
		# Clean up temporary files
		rm -f /tmp/current_cron$$ /tmp/new_cron$$
	fi

	# Clean up any remaining build directories (RPM)
	if [[ -d "~/rpmbuild" ]]; then
		echo "[+] Removing RPM build directory '~/rpmbuild'..."
		rm -rf ~/rpmbuild
		echo "[+] RPM build directory removed."
	fi

	# Clean up any remaining package directories (DPKG)
	if [[ -d "${PACKAGE_NAME}" ]]; then
		echo "[+] Removing package directory '${PACKAGE_NAME}'..."
		rm -rf "${PACKAGE_NAME}"
		echo "[+] Package directory removed."
	fi

	# Remove any lingering files in /var/lib/dpkg/info (DPKG)
	if [[ -d "/var/lib/dpkg/info" ]]; then
		echo "[+] Cleaning up '/var/lib/dpkg/info'..."
		rm -f "/var/lib/dpkg/info/${PACKAGE_NAME}."*
		echo "[+] Cleanup completed."
	fi

	# Remove any package files left in the home directory
	if [[ -f "~/${PACKAGE_NAME}.deb" || -f "~/${PACKAGE_NAME}.rpm" ]]; then
		echo "[+] Removing package files '~/${PACKAGE_NAME}.deb' and/or '~/${PACKAGE_NAME}.rpm'..."
		rm -f ~/${PACKAGE_NAME}.deb ~/${PACKAGE_NAME}.rpm
		echo "[+] Package files removed."
	fi

	return 0
}
