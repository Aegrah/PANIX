revert_cron() {

	usage_revert_cron() {
		echo "Usage: ./panix.sh --revert cron"
		echo "Reverts any changes made by the setup_cron module."
	}

    # Check if crontab command is available
    if ! command -v crontab &> /dev/null; then
        echo "Error: 'crontab' command not found."
        return 1
    fi

    if check_root; then
        # For root user, remove the cron file in /etc/cron.d
        cron_file="/etc/cron.d/freedesktop_timesync1"
        if [[ -f "$cron_file" ]]; then
            rm -f "$cron_file"
            if [[ $? -eq 0 ]]; then
                echo "[+] Removed cron file $cron_file."
            else
                echo "[-] Failed to remove cron file $cron_file."
            fi
        else
            echo "[-] Cron file $cron_file does not exist. No action needed."
        fi
    else
        # For non-root users, remove the cron job from the user's crontab
        # Identify the command pattern to remove
        command_pattern="/bin/bash -c 'sh -i >& /dev/tcp/"

        # Get current crontab
        crontab -l > /tmp/current_cron$$ 2>/dev/null
        if [[ $? -ne 0 ]]; then
            echo "[-] No crontab for user $(whoami). No action needed."
            rm -f /tmp/current_cron$$
            return 0
        fi

        # Remove the line containing the command pattern
        grep -v "$command_pattern" /tmp/current_cron$$ > /tmp/new_cron$$

        # Install the new crontab
        crontab /tmp/new_cron$$
        if [[ $? -eq 0 ]]; then
            echo "[+] Removed cron job from user crontab."
        else
            echo "[-] Failed to update user crontab."
        fi

        # Clean up temporary files
        rm -f /tmp/current_cron$$ /tmp/new_cron$$
    fi

    return 0
}
