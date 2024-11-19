RED='\033[0;31m'
NC='\033[0m'

print_banner() {
	echo ""
	echo " __                      "
	echo "|__)  /\  |\\ | | \\_/   "
	echo "|    /~~\\ | \\| | / \\  "
	echo "                         "
	echo "@RFGroenewoud"
	echo ""
}

check_root() {
	if [[ $EUID -ne 0 ]]; then
		return 1
	else
		return 0
	fi
}

usage_user() {
	echo -e "${RED}[!] Warning: More features are available when running as root.${NC}"
	echo ""
	echo "Low Privileged User Options:"
	echo ""
	echo "  --at                  At job persistence"
	echo "  --authorized-keys     Add public key to authorized keys"
	echo "  --bind-shell          Execute backgrounded bind shell"
	echo "  --cron                Cron job persistence"
	echo "  --docker-container    Docker container with host escape (requires docker group permissions)"
	echo "  --git                 Git persistence"
	echo "  --shell-profile       Shell profile persistence"
	echo "  --ssh-key             SSH key persistence"
	echo "  --systemd             Systemd service persistence"
	echo "  --xdg                 XDG autostart persistence"
	echo "  --revert              Revert most changes made by PANIX' default options"
	echo "  --quiet (-q)          Quiet mode (no banner)"
}

usage_root() {
	echo ""
	echo "Root User Options:"
	echo ""
	echo "  --at                  At job persistence"
	echo "  --authorized-keys     Add public key to authorized keys"
	echo "  --backdoor-user       Create backdoor user"
	echo "  --bind-shell          Execute backgrounded bind shell"
	echo "  --cap                 Add capabilities persistence"
	echo "  --create-user         Create a new user"
	echo "  --cron                Cron job persistence"
	echo "  --docker-container    Docker container with host escape"
	echo "  --generator           Generator persistence"
	echo "  --git                 Git hook/pager persistence"
	echo "  --initd               SysV Init (init.d) persistence"
	echo "  --lkm                 Loadable Kernel Module (LKM) persistence"
	echo "  --malicious-package   Build and Install a package for persistence (DPKG/RPM)"
	echo "  --motd                Message Of The Day (MOTD) persistence (not available on RHEL derivatives)"
	echo "  --package-manager     Package Manager persistence (APT/YUM/DNF)"
	echo "  --passwd-user         Add user to /etc/passwd directly"
	echo "  --password-change     Change user password"
	echo "  --rc-local            Run Control (rc.local) persistence"
	echo "  --rootkit             Diamorphine (LKM) rootkit persistence"
	echo "  --shell-profile       Shell profile persistence"
	echo "  --ssh-key             SSH key persistence"
	echo "  --sudoers             Sudoers persistence"
	echo "  --suid                SUID persistence"
	echo "  --system-binary       System binary persistence"
	echo "  --systemd             Systemd service persistence"
	echo "  --udev                Udev (driver) persistence"
	echo "  --xdg                 XDG autostart persistence"
	echo "  --revert              Revert most changes made by PANIX' default options"
	echo "  --quiet (-q)          Quiet mode (no banner)"
	echo ""
}
