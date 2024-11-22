revert_package_manager() {
	usage_revert_package_manager() {
		echo "Usage: ./panix.sh --revert package-manager"
		echo "Reverts any changes made by the setup_package_manager_persistence module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Revert APT persistence
	if [[ -f "/etc/apt/apt.conf.d/01python-upgrades" ]]; then
		echo "[+] Removing malicious APT configuration..."
		rm -f "/etc/apt/apt.conf.d/01python-upgrades"
		echo "[+] Malicious APT configuration removed."
	else
		echo "[-] Malicious APT configuration not found."
	fi

	# Revert YUM persistence
	if [[ -f "/usr/lib/yumcon" ]] || [[ -f "/usr/lib/yum-plugins/yumcon.py" ]] || [[ -f "/etc/yum/pluginconf.d/yumcon.conf" ]]; then
		echo "[+] Removing malicious YUM configurations and scripts..."

		# Remove the malicious script
		if [[ -f "/usr/lib/yumcon" ]]; then
			rm -f "/usr/lib/yumcon"
			echo "[+] Removed /usr/lib/yumcon."
		fi

		# Remove the YUM plugin
		if [[ -f "/usr/lib/yum-plugins/yumcon.py" ]]; then
			rm -f "/usr/lib/yum-plugins/yumcon.py"
			echo "[+] Removed /usr/lib/yum-plugins/yumcon.py."
		fi

		# Remove the plugin configuration
		if [[ -f "/etc/yum/pluginconf.d/yumcon.conf" ]]; then
			rm -f "/etc/yum/pluginconf.d/yumcon.conf"
			echo "[+] Removed /etc/yum/pluginconf.d/yumcon.conf."
		fi

		echo "[+] Malicious YUM configurations and scripts removed."
	else
		echo "[-] Malicious YUM configurations and scripts not found."
	fi

	# Revert DNF persistence
	python_version=$(ls /usr/lib | grep -oP 'python3\.\d+' | head -n 1)
	if [[ -f "/usr/lib/${python_version}/site-packages/dnfcon" ]] || [[ -f "/usr/lib/${python_version}/site-packages/dnf-plugins/dnfcon.py" ]] || [[ -f "/etc/dnf/plugins/dnfcon.conf" ]]; then
		echo "[+] Removing malicious DNF configurations and scripts..."

		# Remove the malicious script
		if [[ -f "/usr/lib/${python_version}/site-packages/dnfcon" ]]; then
			rm -f "/usr/lib/${python_version}/site-packages/dnfcon"
			echo "[+] Removed /usr/lib/${python_version}/site-packages/dnfcon."
		fi

		# Remove the DNF plugin
		if [[ -f "/usr/lib/${python_version}/site-packages/dnf-plugins/dnfcon.py" ]]; then
			rm -f "/usr/lib/${python_version}/site-packages/dnf-plugins/dnfcon.py"
			echo "[+] Removed /usr/lib/${python_version}/site-packages/dnf-plugins/dnfcon.py."
		fi

		# Remove the plugin configuration
		if [[ -f "/etc/dnf/plugins/dnfcon.conf" ]]; then
			rm -f "/etc/dnf/plugins/dnfcon.conf"
			echo "[+] Removed /etc/dnf/plugins/dnfcon.conf."
		fi

		echo "[+] Malicious DNF configurations and scripts removed."
	else
		echo "[-] Malicious DNF configurations and scripts not found."
	fi

	return 0
}
