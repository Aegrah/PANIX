revert_web_shell() {
    usage_revert_web_shell() {
        echo "Usage: ./panix.sh --revert web-shell"
        echo "Reverts any changes made by the setup_web_shell module."
    }

    # Determine if the script is run as root
    if [[ "$(id -u)" -eq 0 ]]; then
        is_root=true
    else
        is_root=false
    fi

    # Function to display usage if needed
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        usage_revert_web_shell
        return 0
    fi

    # Define system users to skip (modify this array if certain users should not be processed)
    system_users=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "cups-pk-helper" "dnsmasq-dhcp" "sshd" "polkitd")

    # Function to check if a user is a system user
    is_system_user() {
        local user="$1"
        for sys_user in "${system_users[@]}"; do
            if [[ "$user" == "$sys_user" ]]; then
                return 0
            fi
        done
        return 1
    }

    # Function to determine web server directory based on user privileges
    determine_web_dir() {
        local user="$1"
        if [[ "$user" == "root" ]]; then
            echo "/var/www/html/panix/"
        else
            echo "$HOME/panix/"
        fi
    }

    # Function to find and kill web server processes serving a specific directory
    kill_web_server_processes() {
        local web_dir="$1"

        echo "[+] Identifying web server processes serving $web_dir..."

        # Find PIDs of php -S processes serving the web_dir
        php_pids=$(ps aux | grep "[p]hp -S" | grep "$web_dir" | awk '{print $2}')

        # Find PIDs of python3 -m http.server or python -m CGIHTTPServer serving the web_dir
        python3_pids=$(ps aux | grep "[p]ython3 -m http.server" | grep "$web_dir" | awk '{print $2}')
        python_pids=$(ps aux | grep "[p]ython -m CGIHTTPServer" | grep "$web_dir" | awk '{print $2}')

        all_pids="$php_pids $python3_pids $python_pids"

        if [[ -z "$all_pids" ]]; then
            echo "[-] No web server processes found serving $web_dir."
        else
            for pid in $all_pids; do
                kill -9 "$pid" && echo "[+] Killed process $pid serving $web_dir."
            done
        fi
    }

    # Function to remove the web server directory
    remove_web_dir() {
        local web_dir="$1"
        if [[ -d "$web_dir" ]]; then
            rm -rf "$web_dir"
            if [[ $? -eq 0 ]]; then
                echo "[+] Removed web server directory: $web_dir"
            else
                echo "[-] Failed to remove web server directory: $web_dir"
            fi
        else
            echo "[-] Web server directory not found: $web_dir. Skipping removal."
        fi
    }

    # Function to revert web shells for a single user
    revert_user_web_shell() {
        local user="$1"
        local web_dir=$(determine_web_dir "$user")

        echo "[+] Reverting web shell for user '$user' at: $web_dir"

        # Kill web server processes
        kill_web_server_processes "$web_dir"

        # Remove web server directory
        remove_web_dir "$web_dir"
    }

    # Main revert logic based on execution context
    if [[ "$is_root" == true ]]; then
        echo "[+] Running as root. Reverting web shells for root and all non-system users."

        # Revert web shell for root
        revert_user_web_shell "root"

        # Iterate over all user directories in /home
        for user_home in /home/*; do
            if [[ -d "$user_home" ]]; then
                user_name=$(basename "$user_home")
                if is_system_user "$user_name"; then
                    echo "[-] Skipping system user '$user_name'."
                    continue
                fi
                revert_user_web_shell "$user_name"
            fi
        done
    else
        # Non-root execution: revert web shell for the current user only
        current_user=$(whoami)
        echo "[+] Running as non-root. Reverting web shell for user '$current_user'."

        revert_user_web_shell "$current_user"
    fi

    return 0
}
