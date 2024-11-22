revert_ssh_key() {
    usage_revert_ssh_key() {
        echo "Usage: ./panix.sh --revert ssh-key"
        echo "Reverts any changes made by the setup_ssh_key module."
    }

    # Determine if the script is run as root
    if [[ "$(id -u)" -eq 0 ]]; then
        is_root=true
    else
        is_root=false
    fi

    # Function to backup a file if not already backed up
    backup_file() {
        local file_path="$1"
        if [[ -f "$file_path" && ! -f "${file_path}.backup" ]]; then
            cp "$file_path" "${file_path}.backup"
            echo "[+] Backup of $file_path created at ${file_path}.backup"
        elif [[ -f "$file_path" && -f "${file_path}.backup" ]]; then
            echo "[!] Backup of $file_path already exists at ${file_path}.backup"
        else
            echo "[-] File not found: $file_path. Skipping backup."
        fi
    }

    # Function to remove a file if it exists
    remove_file() {
        local file_path="$1"
        if [[ -f "$file_path" ]]; then
            rm -f "$file_path"
            echo "[+] Removed file: $file_path"
        else
            echo "[-] File not found: $file_path"
        fi
    }

    # Function to remove a public key from authorized_keys
    remove_public_key() {
        local pub_key_content="$1"
        local auth_keys="$2"
        if grep -Fq "$pub_key_content" "$auth_keys"; then
            sed -i "\|$pub_key_content|d" "$auth_keys"
            echo "[+] Removed public key from: $auth_keys"
        else
            echo "[-] Public key not found in: $auth_keys"
        fi
    }

    # Function to process a single user's SSH keys
    process_user_ssh_keys() {
        local user_home="$1"
        local user_name="$2"

        local ssh_dir="$user_home/.ssh"
        local private_key_path="$ssh_dir/id_rsa1822"
        local public_key_path="$ssh_dir/id_rsa1822.pub"
        local authorized_keys_path="$ssh_dir/authorized_keys"

        # Check if .ssh directory exists
        if [[ ! -d "$ssh_dir" ]]; then
            echo "[-] .ssh directory not found for user '$user_name' at: $ssh_dir. Skipping."
            return
        fi

        # Backup authorized_keys
        if [[ -f "$authorized_keys_path" ]]; then
            backup_file "$authorized_keys_path"
        else
            echo "[-] authorized_keys file not found at: $authorized_keys_path. Skipping backup."
        fi

        # Check if public key exists
        if [[ -f "$public_key_path" ]]; then
            # Read the public key content
            pub_key_content=$(cat "$public_key_path")

            # Remove the public key entry from authorized_keys
            if [[ -f "$authorized_keys_path" ]]; then
                remove_public_key "$pub_key_content" "$authorized_keys_path"
            else
                echo "[-] authorized_keys file not found at: $authorized_keys_path. Skipping removal of public key."
            fi

            # Remove the SSH key files
            remove_file "$private_key_path"
            remove_file "$public_key_path"

            # Optionally, remove the .ssh directory if it's empty
            if [[ -d "$ssh_dir" ]]; then
                if [[ -z "$(ls -A "$ssh_dir")" ]]; then
                    rm -rf "$ssh_dir"
                    echo "[+] Removed empty .ssh directory: $ssh_dir"
                else
                    echo "[+] .ssh directory not empty after removals: $ssh_dir"
                fi
            fi
        else
            echo "[-] Public key file not found at: $public_key_path. Skipping removal from authorized_keys."
        fi
    }

    # Define system users to skip (if any). Modify this array if certain users should not be processed.
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

    # Collect users to process
    users_to_process=()

    if [[ "$is_root" == true ]]; then
        echo "[+] Running as root. Reverting SSH keys for root and all non-system users."

        # Add root user
        users_to_process+=("root")

        # Iterate over all user directories in /home
        for user_home in /home/*; do
            if [[ -d "$user_home" ]]; then
                user_name=$(basename "$user_home")
                if is_system_user "$user_name"; then
                    echo "[-] Skipping system user '$user_name'."
                    continue
                fi
                users_to_process+=("$user_name")
            fi
        done
    else
        # Non-root execution: process only the current user
        current_user=$(whoami)
        echo "[+] Running as non-root. Reverting SSH keys for user '$current_user'."
        users_to_process+=("$current_user")
    fi

    # Process each user
    for user in "${users_to_process[@]}"; do
        if [[ "$user" == "root" ]]; then
            user_home="/root"
        else
            user_home="/home/$user"
        fi

        echo "[+] Processing SSH keys for user '$user' at: $user_home/.ssh"
        process_user_ssh_keys "$user_home" "$user"
    done

    return 0
}
