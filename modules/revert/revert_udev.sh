revert_udev() {
	usage_revert_udev() {
		echo "Usage: ./panix.sh --revert udev"
		echo "Reverts any changes made by the setup_udev module."
	}

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
		fi
	}

	# Function to remove a udev rule
	remove_udev_rule() {
		local rule_name="$1"
		local rule_path="/etc/udev/rules.d/$rule_name"
		remove_file "$rule_path"
	}

	# Function to remove a script from /usr/bin or /bin
	remove_script() {
		local script_name="$1"
		remove_file "/usr/bin/$script_name"
		remove_file "/bin/$script_name"
	}

	# Function to stop and disable a systemd service
	remove_systemd_service() {
		local service_name="$1"
		local service_path="/etc/systemd/system/$service_name.service"

		if systemctl is-active --quiet "$service_name"; then
			systemctl stop "$service_name"
			echo "[+] Stopped systemd service: $service_name"
		else
			echo "[-] Systemd service not running: $service_name"
		fi

		if systemctl is-enabled --quiet "$service_name"; then
			systemctl disable "$service_name"
			echo "[+] Disabled systemd service: $service_name"
		else
			echo "[-] Systemd service not enabled: $service_name"
		fi

		remove_file "$service_path"
	}

	# Function to remove a cron job containing a specific string
	remove_cron_job() {
		local job_string="$1"
		crontab -l | grep -v "$job_string" | crontab -
		echo "[+] Removed cron jobs containing: $job_string"
	}

	# Remove udev rules and associated scripts
	echo "[+] Removing udev rules and associated scripts..."

	# Remove sedexp components
	remove_script "sedexp"
	remove_udev_rule "10-sedexp.rules"
	remove_file "/tmp/sedexp"

	# Remove atest components
	remove_script "atest"
	remove_udev_rule "11-atest.rules"

	# Remove crontest components
	remove_script "crontest"
	remove_udev_rule "11-crontest.rules"
	remove_cron_job "/usr/bin/crontest"

	# Remove systemdtest components
	remove_systemd_service "systemdtest"
	remove_udev_rule "12-systemdtest.rules"

	# Remove any custom udev rules added by the setup function
	# Assuming custom rules are stored with names starting with "10-backdoor.rules"
	for custom_rule in /etc/udev/rules.d/10-backdoor.rules; do
		if [[ -f "$custom_rule" ]]; then
			remove_file "$custom_rule"
		fi
	done

	# Reload udev rules
	echo "[+] Reloading udev rules..."
	udevadm control --reload
	udevadm trigger
	echo "[+] Udev rules reloaded."

	return 0
}
