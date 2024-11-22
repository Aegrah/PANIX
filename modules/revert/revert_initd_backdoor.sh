revert_initd() {
	usage_revert_initd() {
		echo "Usage: ./panix.sh --revert initd"
		echo "Reverts any changes made by the setup_initd_backdoor module."
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local initd_path="/etc/init.d/ssh-procps"
	local service_name=$(basename "$initd_path")
	local service_path="/etc/systemd/system/${service_name}.service"

	# Stop the service if it's running
	if systemctl is-active --quiet "$service_name.service"; then
		echo "[+] Stopping '$service_name' service..."
		systemctl stop "$service_name.service"
	else
		echo "[-] '$service_name' service is not running."
	fi

	# Disable the service if it's enabled
	if systemctl is-enabled --quiet "$service_name.service"; then
		echo "[+] Disabling '$service_name' service..."
		systemctl disable "$service_name.service"
	else
		echo "[-] '$service_name' service is not enabled."
	fi

	# Remove the systemd service file
	if [[ -f "$service_path" ]]; then
		echo "[+] Removing systemd service file '$service_path'..."
		rm -f "$service_path"
	else
		echo "[-] Systemd service file '$service_path' not found."
	fi

	# Remove the init.d script
	if [[ -f "$initd_path" ]]; then
		echo "[+] Removing init.d script '$initd_path'..."
		rm -f "$initd_path"
	else
		echo "[-] Init.d script '$initd_path' not found."
	fi

	# Remove symlinks created by update-rc.d
	if command -v update-rc.d &> /dev/null; then
		echo "[+] Removing init.d symlinks using 'update-rc.d'..."
		update-rc.d -f "$service_name" remove
	fi

	# Remove symlinks created by chkconfig
	if command -v chkconfig &> /dev/null; then
		echo "[+] Removing init.d symlinks using 'chkconfig'..."
		chkconfig --del "$service_name"
	fi

	# Reload systemd daemon
	echo "[+] Reloading systemd daemon..."
	systemctl daemon-reload

	# Kill any processes started by the init.d script
	echo "[+] Killing any processes started by '$initd_path'..."
	pkill -f "$initd_path"

	return 0
}
