display_mitre_matrix() {
	echo -e "\n\033[1;34mMITRE ATT&CK Matrix - Persistence Techniques Supported by PANIX\033[0m\n"
	printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" "Persistence Method" "Technique Name" "Technique ID" "Sub-technique Name" "Sub-technique ID" "URL"
	printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" "-------------------" "--------------" "-------------" "-----------------" "---------------" "---------------------------------------------"

	printf "%-25s %-40s %-15s %-40s %-20s %-70s\n" \
		"--at" "Scheduled Task" "T1053" "At" "T1053.002" "https://attack.mitre.org/techniques/T1053/002" \
		"--authorized-keys" "Account Manipulation" "T1098" "SSH Authorized Keys" "T1098.004" "https://attack.mitre.org/techniques/T1098/004" \
		"--backdoor-user" "Create Account" "T1136" "Local Account" "T1136.001" "https://attack.mitre.org/techniques/T1136/001" \
		"--bind-shell" "Command and Scripting Interpreter" "T1059" "Unix Shell" "T1059.004" "https://attack.mitre.org/techniques/T1059/004" \
		"--cap" "Abuse Elevation Control Mechanism" "T1548" "N/A" "N/A" "https://attack.mitre.org/techniques/T1548" \
		"--create-user" "Create Account" "T1136" "Local Account" "T1136.001" "https://attack.mitre.org/techniques/T1136/001" \
		"--cron" "Scheduled Task" "T1053" "Cron" "T1053.003" "https://attack.mitre.org/techniques/T1053/003" \
		"--docker-container" "Escape to Host" "T1610" "N/A" "N/A" "https://attack.mitre.org/techniques/T1610" \
		"--generator" "Create or Modify System Process" "T1543" "Systemd Service" "T1543.002" "https://attack.mitre.org/techniques/T1543/002" \
		"--git" "Event Triggered Execution" "T1546" "N/A" "N/A" "https://attack.mitre.org/techniques/T1546" \
		"--initd" "Boot or Logon Initialization Scripts" "T1037" "N/A" "N/A" "https://attack.mitre.org/techniques/T1037" \
		"--ld-preload" "Hijack Execution Flow" "T1574" "Dynamic Linker Hijacking" "T1574.006" "https://attack.mitre.org/techniques/T1574/006" \
		"--lkm" "Boot or Logon Autostart Execution" "T1547" "Kernel Modules and Extensions" "T1547.006" "https://attack.mitre.org/techniques/T1547/006" \
		"--malicious-package" "Event Triggered Execution" "T1546" "Installer Packages" "T1546.016" "https://attack.mitre.org/techniques/T1546/016" \
		"--motd" "Boot or Logon Initialization Scripts" "T1037" "N/A" "N/A" "https://attack.mitre.org/techniques/T1037" \
		"--package-manager" "Event Triggered Execution" "T1546" "Installer Packages" "T1546.016" "https://attack.mitre.org/techniques/T1546/016" \
		"--pam" "Modify Authentication Process" "T1556" "Pluggable Authentication Modules" "T1556.003" "https://attack.mitre.org/techniques/T1556/003" \
		"--passwd-user" "Account Manipulation" "T1098" "N/A" "N/A" "https://attack.mitre.org/techniques/T1098" \
		"--password-change" "Account Manipulation" "T1098" "N/A" "N/A" "https://attack.mitre.org/techniques/T1098" \
		"--rc-local" "Boot or Logon Initialization Scripts" "T1037" "RC Scripts" "T1037.004" "https://attack.mitre.org/techniques/T1037/004" \
		"--reverse-shell" "Command and Scripting Interpreter" "T1059" "Unix Shell" "T1059.004" "https://attack.mitre.org/techniques/T1059/004" \
		"--rootkit" "Rootkit" "T1014" "N/A" "N/A" "https://attack.mitre.org/techniques/T1014" \
		"--shell-profile" "Event Triggered Execution" "T1546" "Unix Shell Configuration Modification" "T1546.004" "https://attack.mitre.org/techniques/T1546/004" \
		"--ssh-key" "Account Manipulation" "T1098" "SSH Authorized Keys" "T1098.004" "https://attack.mitre.org/techniques/T1098/004" \
		"--sudoers" "Abuse Elevation Control Mechanism" "T1548" "Sudo and Sudo Caching" "T1548.003" "https://attack.mitre.org/techniques/T1548/003" \
		"--suid" "Abuse Elevation Control Mechanism" "T1548" "Setuid and Setgid" "T1548.001" "https://attack.mitre.org/techniques/T1548/001" \
		"--system-binary" "Compromise Host Software Binary" "T1554" "N/A" "N/A" "https://attack.mitre.org/techniques/T1554" \
		"--systemd" "Create or Modify System Process" "T1543" "Systemd Service" "T1543.002" "https://attack.mitre.org/techniques/T1543/002" \
		"--udev" "Event Triggered Execution" "T1546" "Udev Rules" "T1546.017" "https://attack.mitre.org/techniques/T1546/017" \
		"--web-shell" "Server Software Component" "T1505" "Web Shell" "T1505.003" "https://attack.mitre.org/techniques/T1505/003" \
		"--xdg" "Boot or Logon Autostart Execution" "T1547" "XDG Autostart Entries" "T1547.013" "https://attack.mitre.org/techniques/T1547/013"
	
	echo -e "\n\033[1;32mLegend:\033[0m"
	echo "Technique: High-level MITRE ATT&CK technique."
	echo "Sub-Technique: Specific sub-technique under a high-level technique."
	echo "N/A: No specific sub-technique defined for this method."
	echo "URL: Link to the official MITRE ATT&CK page for further details."
	echo ""
}
