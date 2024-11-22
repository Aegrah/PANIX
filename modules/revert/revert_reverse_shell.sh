revert_reverse_shell() {
	usage_revert_reverse_shell() {
		echo "Usage: ./panix.sh --revert reverse-shell"
		echo "Reverts any changes made by the setup_reverse_shell module."
	}

	# Ensure the function is run as root
	if ! check_root; then
		echo "Error: This function can only be run as root."
		return 1
	fi

	# List of possible mechanisms used in the setup function
	local mechanisms=("awk" "bash" "busybox" "gawk" "ksh" "lua" "nawk" "nc" "node" "openssl" "perl" "php" "python" "python3" "ruby" "sh-udp" "socat" "telnet")

	# Function to kill processes based on patterns
	kill_processes() {
		local pattern="$1"
		local pids

		# Use pgrep to find PIDs matching the pattern
		pids=$(pgrep -f "$pattern")

		if [[ -n "$pids" ]]; then
			echo "[+] Terminating processes matching pattern '$pattern'..."
			# Terminate each PID individually to handle cases where some PIDs may no longer exist
			for pid in $pids; do
				if kill -9 "$pid" 2>/dev/null; then
					echo "[+] Successfully terminated PID $pid"
				else
					echo "[-] Failed to terminate PID $pid (No such process)"
				fi
			done
		fi
	}

	# Iterate over mechanisms and attempt to kill associated processes
	for mech in "${mechanisms[@]}"; do
		case $mech in
			awk|gawk|nawk)
				kill_processes "awk -v RHOST"
				;;
			bash)
				kill_processes "bash -i >& /dev/tcp"
				;;
			busybox)
				kill_processes "busybox nc"
				;;
			ksh)
				kill_processes "ksh -c 'ksh -i'"
				;;
			lua)
				kill_processes "lua -e"
				;;
			nc)
				kill_processes "nc.traditional -e /bin/sh"
				kill_processes "nc -e /bin/sh"
				;;
			node)
				kill_processes "node -e"
				;;
			openssl)
				kill_processes "openssl s_client"
				;;
			perl)
				kill_processes "perl -e"
				;;
			php)
				kill_processes "php -r"
				;;
			python)
				kill_processes "python -c"
				;;
			python3)
				kill_processes "python3 -c"
				;;
			ruby)
				kill_processes "ruby -rsocket -e"
				;;
			sh-udp)
				kill_processes "sh -i >& /dev/udp"
				;;
			socat)
				kill_processes "socat tcp-connect"
				;;
			telnet)
				kill_processes "telnet"
				;;
			*)
				# Do nothing for unrecognized mechanisms
				;;
		esac
	done

	return 0
}
