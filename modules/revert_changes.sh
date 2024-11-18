revert_changes() {
	local current_user=$(whoami)
	local ssh_dir="/home/$current_user/.ssh"
	local is_root=false
	local in_docker_group=false
	local malicious_entry="/dev/tcp"

	# Check if running as root
	if [ "$(id -u)" -eq 0 ]; then
		is_root=true
	fi

	# Check if the user is in the docker group
	if groups $current_user | grep -q '\bdocker\b'; then
		in_docker_group=true
	fi

	if $is_root; then
		echo "[*] Running as root..."
	else
		echo "[*] Running as user..."
	fi

	# Systemd
	echo "[*] Cleaning Systemd persistence methods..."
	if $is_root; then
		systemctl stop dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		systemctl disable dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		rm -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service
		rm -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer
	fi
	rm -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service
	rm -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer
	if ! $is_root; then
		systemctl --user stop dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
		systemctl --user disable dbus-org.freedesktop.resolved.service dbus-org.freedesktop.resolved.timer 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Systemd"

	# Systemd Generator
	echo "[*] Cleaning Systemd Generator persistence methods..."
	if $is_root; then
		systemctl stop generator.service 2>/dev/null
		systemctl disable generator.service 2>/dev/null
		rm -f /usr/lib/systemd/system-generators/makecon
		rm -f /usr/lib/systemd/system-generators/generator
		rm -f /run/systemd/system/generator.service
		rm -f /run/systemd/system/multi-user.target.wants/generator.service
	else
		systemctl --user stop generator.service 2>/dev/null
		systemctl --user disable generator.service 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Systemd Generator"

	# Cron
	echo "[*] Cleaning Cron persistence methods..."
	if $is_root; then
		rm -f /etc/cron.d/freedesktop_timesync1
		for file in /etc/cron*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	crontab -l | grep -v "$malicious_entry" | crontab -
	echo "[+] Successfully cleaned persistence method Cron"

	# At
	echo "[*] Cleaning At persistence methods..."
	if $is_root; then
		for file in /var/spool/cron/atjobs/*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method At"

	# Shell profile
	echo "[*] Cleaning Shell profile persistence methods..."
	if $is_root; then
		[ -e "/etc/profile" ] && sed -i "/$malicious_entry/ d" /etc/profile 2>/dev/null
	fi
	[ -e "/home/$current_user/.bash_profile" ] && sed -i "/$malicious_entry/ d" /home/$current_user/.bash_profile 2>/dev/null
	echo "[+] Successfully cleaned persistence method Shell profile"

	# XDG
	echo "[*] Cleaning XDG persistence methods..."
	if $is_root; then
		rm -f /etc/xdg/autostart/pkc12-register.desktop
		rm -f /etc/xdg/pkc12-register
	fi
	rm -f /home/$current_user/.config/autostart/user-dirs.desktop
	rm -f /home/$current_user/.config/autostart/.user-dirs
	echo "[+] Successfully cleaned persistence method XDG"

	# SSH
	echo "[*] Cleaning SSH persistence methods..."
	rm -f $ssh_dir/id_rsa1822
	rm -f $ssh_dir/id_rsa1822.pub
	echo "[+] Successfully cleaned persistence method SSH"

	# Sudoers
	echo "[*] Cleaning Sudoers persistence methods..."
	if $is_root; then
		rm -f /etc/sudoers.d/$current_user
	fi
	echo "[+] Successfully cleaned persistence method Sudoers"

	# Setuid
	echo "[*] Cleaning Setuid persistence methods..."
	if $is_root; then
		for bin in find dash python python3; do
			[ -e "$(which $bin)" ] && chmod u-s $(which $bin) 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method Setuid"

	# MOTD
	echo "[*] Cleaning MOTD persistence methods..."
	if $is_root; then
		rm -f /etc/update-motd.d/137-python-upgrades
		for file in /etc/update-motd.d/*; do
			[ -e "$file" ] && sed -i "/$malicious_entry/ d" $file 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method MOTD"

	# rc.local
	echo "[*] Cleaning rc.local persistence methods..."
	if $is_root; then
		[ -e "/etc/rc.local" ] && sed -i "/$malicious_entry/ d" /etc/rc.local 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method rc.local"

	# initd
	echo "[*] Cleaning initd persistence methods..."
	if $is_root; then
		rm -f /etc/init.d/ssh-procps
	fi
	echo "[+] Successfully cleaned persistence method initd"

	# Package Managers
	echo "[*] Cleaning Package Managers persistence methods..."
	if $is_root; then
		rm -f /etc/apt/apt.conf.d/01python-upgrades
		rm -f /usr/lib/yumcon
		rm -f /usr/lib/yum-plugins/yumcon.py
		rm -f /etc/yum/pluginconf.d/yumcon.conf
		local python_version=$(ls /usr/lib | grep -oP 'python3\.\d+' | head -n 1)
		[ -n "$python_version" ] && rm -f /usr/lib/$python_version/site-packages/dnfcon
		rm -f /etc/dnf/plugins/dnfcon.conf
		[ -n "$python_version" ] && rm -f /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
	fi
	echo "[+] Successfully cleaned persistence method Package Managers"

	# setcap
	echo "[*] Cleaning setcap persistence methods..."
	if $is_root; then
		for bin in perl ruby php python python3 node; do
			[ -e "$(which $bin)" ] && setcap -r $(which $bin) 2>/dev/null
		done
	fi
	echo "[+] Successfully cleaned persistence method setcap"

	# Bind shell
	echo "[*] Cleaning Bind shell persistence methods..."
	if $is_root; then
		pkill -f /tmp/bd86 2>/dev/null
		pkill -f /tmp/bd64 2>/dev/null
	fi
	rm -f /tmp/bd86
	rm -f /tmp/bd64
	echo "[+] Successfully cleaned persistence method Bind shell"

	# Backdoor binaries
	echo "[*] Cleaning Backdoor binaries persistence methods..."
	if $is_root; then
		for binary in cat ls; do
			original=$(which $binary).original
			if [ -f "$original" ]; then
				mv "$original" "$(which $binary)" 2>/dev/null
				if [ $? -eq 0 ]; then
					echo "[+] Successfully restored $binary binary"
				else
					echo "[-] Failed to restore $binary binary"
				fi
			else
				echo "[*] No original file for $binary found, skipping..."
			fi
		done
	fi
	echo "[+] Successfully cleaned persistence method Backdoor binaries"

	# udev
	echo "[*] Cleaning udev persistence methods..."
	if $is_root; then
		rm -f /usr/bin/atest
		rm -f /etc/udev/rules.d/10-atest.rules
		rm -f /usr/bin/crontest
		rm -f /etc/udev/rules.d/11-crontest.rules
		rm -f /etc/udev/rules.d/12-systemdtest.rules
		systemctl stop systemdtest.service 2>/dev/null
		systemctl disable systemdtest.service 2>/dev/null
		rm -f /etc/systemd/system/systemdtest.service
	fi
	echo "[+] Successfully cleaned persistence method udev"

	# Git
	echo "[*] Cleaning Git persistence methods..."
	local repos=$(find / -name ".git" -type d 2>/dev/null)

	if [[ -z $repos ]]; then
		echo "[-] No Git repositories found."
	else
		for repo in $repos; do
			local git_repo=$(dirname $repo)
			local pre_commit_file="$git_repo/.git/hooks/pre-commit"
			local git_config="$git_repo/.git/config"
			local user_git_config="/home/$current_user/.gitconfig"

			# Remove malicious pre-commit hook
			if [[ -f $pre_commit_file ]]; then
				if grep -q "$malicious_entry" $pre_commit_file; then
					sed -i "/$malicious_entry/ d" $pre_commit_file
					echo "[+] Removed malicious entry from pre-commit hook in $git_repo"
				fi
			fi

			# Remove malicious pager configuration from repo config
			if [[ -f $git_config ]]; then
				if grep -q "$malicious_entry" $git_config; then
					sed -i "/$malicious_entry/ d" $git_config
					echo "[+] Removed malicious pager from Git config in $git_repo"
				fi
			fi

			# Remove malicious pager configuration from global config
			if [[ -f $user_git_config ]]; then
				if grep -q "$malicious_entry" $user_git_config; then
					sed -i "/$malicious_entry/ d" $user_git_config
					echo "[+] Removed malicious pager from global Git config"
				fi
			fi
		done
	fi
	echo "[+] Successfully cleaned persistence method Git"

	# Docker
	echo "[*] Cleaning Docker persistence methods..."
	if $is_root || $in_docker_group; then
		rm -f /tmp/Dockerfile
		docker stop malicious-container 2>/dev/null
		docker rm malicious-container 2>/dev/null
	fi
	echo "[+] Successfully cleaned persistence method Docker"

	# Malicious package
	echo "[*] Cleaning Malicious package persistence methods..."
	if $is_root; then
		rm -f /var/lib/rpm/panix.rpm
		rm -f /var/lib/dpkg/info/panix.postinst
		sed -i '/panix.rpm/ d' /var/spool/cron/$current_user
		sed -i '/panix.postinst/ d' /var/spool/cron/crontabs/$current_user
	fi
	echo "[+] Successfully cleaned persistence method Malicious package"
}
