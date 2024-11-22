revert_generator() {
	usage_revert_generator() {
		echo "Usage: ./panix.sh --revert generator"
		echo "Reverts any changes made by the setup_generator_persistence module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# Stop the 'generator' service if it's running
	if systemctl is-active --quiet generator.service; then
		echo "[+] Stopping 'generator' service..."
		systemctl stop generator.service
	else
		echo "[-] 'generator' service is not running."
	fi

	# Disable the 'generator' service
	if systemctl is-enabled --quiet generator.service; then
		echo "[+] Disabling 'generator' service..."
		systemctl disable generator.service
	else
		echo "[-] 'generator' service is not enabled."
	fi

	# Remove the scripts
	if [[ -f /usr/lib/systemd/system-generators/makecon ]]; then
		echo "[+] Removing /usr/lib/systemd/system-generators/makecon..."
		rm -f /usr/lib/systemd/system-generators/makecon
	else
		echo "[-] /usr/lib/systemd/system-generators/makecon not found. Skipping."
	fi

	if [[ -f /usr/lib/systemd/system-generators/generator ]]; then
		echo "[+] Removing /usr/lib/systemd/system-generators/generator..."
		rm -f /usr/lib/systemd/system-generators/generator
	else
		echo "[-] /usr/lib/systemd/system-generators/generator not found. Skipping."
	fi

	# Remove the systemd service unit file
	if [[ -f /run/systemd/system/generator.service ]]; then
		echo "[+] Removing /run/systemd/system/generator.service..."
		rm -f /run/systemd/system/generator.service
	else
		echo "[-] /run/systemd/system/generator.service not found. Skipping."
	fi

	# Remove the symlink
	if [[ -L /run/systemd/system/multi-user.target.wants/generator.service ]]; then
		echo "[+] Removing symlink /run/systemd/system/multi-user.target.wants/generator.service..."
		rm -f /run/systemd/system/multi-user.target.wants/generator.service
	else
		echo "[-] Symlink /run/systemd/system/multi-user.target.wants/generator.service not found. Skipping."
	fi

	# Reload systemd daemon
	echo "[+] Reloading systemd daemon..."
	systemctl daemon-reload

	# Kill any lingering processes started by 'makecon'
	echo "[+] Killing any lingering 'makecon' processes..."
	pkill -f "/usr/lib/systemd/system-generators/makecon"

	return 0
}
