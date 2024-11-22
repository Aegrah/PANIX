revert_bind_shell() {
	usage_revert_bind_shell() {
		echo "Usage: ./panix.sh --revert bind-shell"
		echo "Reverts any changes made by the setup_bind_shell module."
	}

	# Kill any running bind shell processes started by setup_bind_shell

	echo "[+] Searchnig for bind shell processes and killing them if present..."

	# Kill shellcode bind shells (/tmp/bd86 and /tmp/bd64)
	if [[ -f /tmp/bd86 ]]; then
		echo "[+] Found /tmp/bd86 binary. Killing process and removing binary..."
		pkill -f "/tmp/bd86"
		rm -f /tmp/bd86
	fi

	if [[ -f /tmp/bd64 ]]; then
		echo "[+] Found /tmp/bd64 binary. Killing process and removing binary..."
		pkill -f "/tmp/bd64"
		rm -f /tmp/bd64
	fi

	# Kill netcat bind shell processes
	if pgrep -f "nc\.traditional.*-l.*-p" > /dev/null; then
		echo "[+] Found Netcat (nc.traditional) bind shell process(es). Killing..."
		pkill -f "nc\.traditional.*-l.*-p"
	fi

	if pgrep -f "nc.*-l.*-p" > /dev/null; then
		echo "[+] Found Netcat bind shell process(es). Killing..."
		pkill -f "nc.*-l.*-p"
	fi

	# Kill Node.js bind shell processes
	if pgrep -f "node -e" > /dev/null; then
		echo "[+] Found Node.js bind shell process(es). Killing..."
		pkill -f "node -e"
	fi

	# Kill Socat bind shell processes
	if pgrep -f "socat TCP-LISTEN" > /dev/null; then
		echo "[+] Found Socat bind shell process(es). Killing..."
		pkill -f "socat TCP-LISTEN"
	fi

	# Kill Socket bind shell processes
	if pgrep -f "socket -svp" > /dev/null; then
		echo "[+] Found Socket bind shell process(es). Killing..."
		pkill -f "socket -svp"
	fi

	# Remove custom binary if known
	# If a custom binary path was used, it should be stored or known; assuming /tmp/custom_bind_shell
	if [[ -f /tmp/custom_bind_shell ]]; then
		echo "[+] Found custom bind shell binary at /tmp/custom_bind_shell. Killing process and removing binary..."
		pkill -f "/tmp/custom_bind_shell"
		rm -f /tmp/custom_bind_shell
	fi

	return 0
}
