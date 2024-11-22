revert_systemd() {
    usage_revert_systemd() {
        echo "Usage: ./panix.sh --revert systemd"
        echo "Reverts any changes made by the setup_systemd module."
    }

    if ! check_root; then
        echo "Error: This function can only be run as root."
        return 1
    fi

    # Revert default services
    default_service_name="dbus-org.freedesktop.resolved.service"
    default_timer_name="dbus-org.freedesktop.resolved.timer"
    default_system_service_path="/usr/local/lib/systemd/system/$default_service_name"
    default_system_timer_path="/usr/local/lib/systemd/system/$default_timer_name"

    # Disable and stop the default system-level timer and service
    if [[ -f "$default_system_service_path" || -f "$default_system_timer_path" ]]; then
        echo "[+] Disabling and stopping default system-level systemd services..."

        systemctl stop "$default_timer_name" 2>/dev/null
        systemctl disable "$default_timer_name" 2>/dev/null

        systemctl stop "$default_service_name" 2>/dev/null
        systemctl disable "$default_service_name" 2>/dev/null

        # Remove the service and timer files
        rm -f "$default_system_service_path" "$default_system_timer_path"

        echo "[+] Removed default system-level systemd service and timer files."
    else
        echo "[-] Default system-level systemd service and timer files not found."
    fi

    # Revert default user-level services
    for user_home in /home/*; do
        if [ -d "$user_home/.config/systemd/user" ]; then
            user_service_path="$user_home/.config/systemd/user/$default_service_name"
            user_timer_path="$user_home/.config/systemd/user/$default_timer_name"
            user_name=$(basename "$user_home")

            if [[ -f "$user_service_path" || -f "$user_timer_path" ]]; then
                echo "[+] Disabling and stopping default user-level systemd services for user '$user_name'..."

                su - "$user_name" -c "systemctl --user stop '$default_timer_name'" 2>/dev/null
                su - "$user_name" -c "systemctl --user disable '$default_timer_name'" 2>/dev/null

                su - "$user_name" -c "systemctl --user stop '$default_service_name'" 2>/dev/null
                su - "$user_name" -c "systemctl --user disable '$default_service_name'" 2>/dev/null

                # Remove the service and timer files
                rm -f "$user_service_path" "$user_timer_path"

                echo "[+] Removed default user-level systemd service and timer files for user '$user_name'."
            else
                echo "[-] Default user-level systemd service and timer files not found for user '$user_name'."
            fi
        fi
    done

    # Reload systemd daemon
    systemctl daemon-reload

    # For each user, reload the user systemd daemon
    for user_home in /home/*; do
        if [ -d "$user_home/.config/systemd/user" ]; then
            user_name=$(basename "$user_home")
            su - "$user_name" -c "systemctl --user daemon-reload" 2>/dev/null
        fi
    done

    # Attempt to detect and remove custom malicious services
    echo "[+] Searching for custom malicious systemd services..."

    # Define directories to search for malicious services
    service_dirs=(
        "/usr/local/lib/systemd/system"
        "/etc/systemd/system"
    )

    # Search for suspicious system-level services
    for dir in "${service_dirs[@]}"; do
        if [ -d "$dir" ]; then
            find "$dir" -type f -name "*.service" -o -name "*.timer" 2>/dev/null | while read -r service_file; do
                # Check if the service file contains suspicious commands
                if grep -Eq "(bash -i >& /dev/tcp|ExecStart=.*bash -c)" "$service_file"; then
                    service_name=$(basename "$service_file")
                    echo "[+] Found suspicious system-level service: '$service_name'"

                    # Disable and stop the service
                    systemctl stop "$service_name" 2>/dev/null
                    systemctl disable "$service_name" 2>/dev/null

                    # Remove the service file
                    rm -f "$service_file"

                    echo "[+] Removed suspicious system-level service: '$service_name'"
                fi
            done
        fi
    done

    # Search for suspicious user-level services
    for user_home in /home/*; do
        if [ -d "$user_home/.config/systemd/user" ]; then
            user_name=$(basename "$user_home")
            find "$user_home/.config/systemd/user/" -type f -name "*.service" -o -name "*.timer" 2>/dev/null | while read -r service_file; do
                if grep -Eq "(bash -i >& /dev/tcp|ExecStart=.*bash -c)" "$service_file"; then
                    service_name=$(basename "$service_file")
                    echo "[+] Found suspicious user-level service for user '$user_name': '$service_name'"

                    # Disable and stop the service
                    su - "$user_name" -c "systemctl --user stop '$service_name'" 2>/dev/null
                    su - "$user_name" -c "systemctl --user disable '$service_name'" 2>/dev/null

                    # Remove the service file
                    rm -f "$service_file"

                    echo "[+] Removed suspicious user-level service for user '$user_name': '$service_name'"
                fi
            done
        fi
    done

    # Reload daemons again
    systemctl daemon-reload

    for user_home in /home/*; do
        if [ -d "$user_home/.config/systemd/user" ]; then
            user_name=$(basename "$user_home")
            su - "$user_name" -c "systemctl --user daemon-reload" 2>/dev/null
        fi
    done

    return 0
}
