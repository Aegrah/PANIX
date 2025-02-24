revert_polkit() {
    usage_revert_polkit() {
        echo "Usage: ./panix.sh --revert polkit"
        echo "Reverts any changes made by the setup_polkit module."
    }

    # Ensure the function is run as root
    if ! check_root; then
        echo "Error: This function can only be run as root."
        return 1
    fi

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

    # Remove .pkla persistence file
    pkla_path="/etc/polkit-1/localauthority/50-local.d/panix.pkla"
    echo "[+] Checking for .pkla persistence file..."
    if [[ -f "$pkla_path" ]]; then
        remove_file "$pkla_path"
    else
        echo "[-] .pkla file not found: $pkla_path"
    fi

    # Remove .rules persistence file
    rules_path="/etc/polkit-1/rules.d/99-panix.rules"
    echo "[+] Checking for .rules persistence file..."
    if [[ -f "$rules_path" ]]; then
        remove_file "$rules_path"
    else
        echo "[-] .rules file not found: $rules_path"
    fi

    # Restart polkit service to apply changes
    echo "[+] Restarting polkit service..."
    if systemctl restart polkit; then
        echo "[+] Polkit service restarted successfully."
    else
        echo "[-] Failed to restart polkit service."
    fi

    return 0
}
