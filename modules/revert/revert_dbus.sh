revert_dbus() {
	usage_revert_dbus() {
		echo "Usage: ./panix.sh --revert dbus"
		echo "Reverts any changes made by the setup_dbus module."
	}

	# Must be executed as root.
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	local service_file="/usr/share/dbus-1/system-services/org.panix.persistence.service"
	local payload_script="/usr/local/bin/dbus-panix.sh"
	local conf_file="/etc/dbus-1/system.d/org.panix.persistence.conf"

	echo "[*] Reverting D-Bus persistence module..."

	# Remove the D-Bus service file.
	if [[ -f "$service_file" ]]; then
		echo "[+] Removing D-Bus service file: $service_file..."
		rm -f "$service_file"
		echo "[+] D-Bus service file removed."
	else
		echo "[-] D-Bus service file not found: $service_file"
	fi

	# Remove the payload script.
	if [[ -f "$payload_script" ]]; then
		echo "[+] Removing payload script: $payload_script..."
		rm -f "$payload_script"
		echo "[+] Payload script removed."
	else
		echo "[-] Payload script not found: $payload_script"
	fi

	# Remove the D-Bus configuration file.
	if [[ -f "$conf_file" ]]; then
		echo "[+] Removing D-Bus configuration file: $conf_file..."
		rm -f "$conf_file"
		echo "[+] D-Bus configuration file removed."
	else
		echo "[-] D-Bus configuration file not found: $conf_file"
	fi

	# Restart D-Bus to apply the changes.
	echo "[*] Restarting D-Bus..."
	systemctl restart dbus
	if [[ $? -eq 0 ]]; then
		echo "[+] D-Bus restarted successfully."
	else
		echo "[-] Failed to restart D-Bus. You may need to restart it manually."
	fi

	echo "[+] D-Bus persistence reverted."
	return 0
}
