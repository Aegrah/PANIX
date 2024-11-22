revert_rc_local() {
    usage_revert_rc_local() {
        echo "Usage: ./panix.sh --revert rc-local"
        echo "Reverts any changes made by the setup_rc_local_backdoor module."
    }

    # Ensure the function is run as root
    if ! check_root; then
        echo "Error: This function can only be run as root."
        return 1
    fi

    # Function to backup /etc/rc.local before making changes
    backup_rc_local() {
        if [[ ! -f /etc/rc.local.backup ]]; then
            cp /etc/rc.local /etc/rc.local.backup
            echo "[+] Backup of /etc/rc.local created at /etc/rc.local.backup."
        else
            echo "[+] Backup of /etc/rc.local already exists at /etc/rc.local.backup."
        fi
    }

    # Function to escape special characters in sed patterns
    escape_sed_pattern() {
        local pattern="$1"
        # Escape |, \, /, and & characters
        printf '%s' "$pattern" | sed 's/[|\\/&]/\\&/g'
    }

    # Function to remove lines matching a pattern from a file
    remove_lines_matching_pattern() {
        local pattern="$1"
        local file="$2"

        # Escape special characters in the pattern
        local escaped_pattern
        escaped_pattern=$(escape_sed_pattern "$pattern")

        if grep -Fq "$pattern" "$file"; then
            sed -i "\|$escaped_pattern|d" "$file"
            echo "[+] Removed lines matching pattern: '$pattern' from $file"
        fi
    }

    # Backup /etc/rc.local
    backup_rc_local

    # Define malicious patterns to search for in /etc/rc.local
    local patterns=(
        "/bin/bash -c 'sh -i >& /dev/tcp/"
        "setsid nohup bash -c 'sh -i >& /dev/tcp/"
        "nohup setsid bash -c 'sh -i >& /dev/tcp/"
        "bash -i >& /dev/tcp/"
        "bash -c 'sh -i >& /dev/tcp/"
        "bash -i > /dev/tcp/"
        "sh -i >& /dev/udp/"
        "bash -c 'bash -i >& /dev/tcp/"
        "bash -c 'sh -i >& /dev/udp/"
        "nohup setsid bash -c 'sh -i >& /dev/tcp/"
        "nohup setsid sh -c 'sh -i >& /dev/tcp/"
    )

    # Remove malicious lines from /etc/rc.local
	if [[ -f /etc/rc.local ]]; then
		echo "[+] Scanning /etc/rc.local for malicious backdoor commands..."
		for pattern in "${patterns[@]}"; do
			remove_lines_matching_pattern "$pattern" "/etc/rc.local"
		done
	fi

    # Check if /etc/rc.local contains only the shebang and is otherwise empty
    if [[ -f /etc/rc.local ]]; then
        # Count non-shebang and non-empty lines
        non_shebang_lines=$(grep -v "^#!" /etc/rc.local | grep -cv "^[[:space:]]*$")
        if [[ "$non_shebang_lines" -eq 0 ]]; then
            echo "[+] /etc/rc.local contains only the shebang or is empty. Removing the file."
            rm -f /etc/rc.local
            echo "[+] Removed /etc/rc.local"
        else
            echo "[+] Remaining content in /etc/rc.local after removing backdoor entries."
        fi
    else
        echo "[-] /etc/rc.local does not exist. No action taken."
    fi

    # Ensure /etc/rc.local has the correct permissions if it still exists
    if [[ -f /etc/rc.local ]]; then
        chmod +x /etc/rc.local
        echo "[+] Set execute permissions on /etc/rc.local"
    fi

    # Ensure /etc/rc.d/rc.local is executable if it exists
    if [[ -f /etc/rc.d/rc.local ]]; then
        chmod +x /etc/rc.d/rc.local
        echo "[+] Set execute permissions on /etc/rc.d/rc.local"
    fi

    echo "[!] If any legitimate entries were removed unintentionally, restore from the backup."
    echo "[!] Run 'sudo cp /etc/rc.local.backup /etc/rc.local' to restore the original /etc/rc.local file if necessary."

    return 0
}
