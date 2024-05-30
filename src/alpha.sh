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
    echo "  --shell-configuration       Shell configuration persistence"
    echo "  --ssh-key                   SSH key persistence"
    echo "  --systemd                   Systemd service persistence"
    echo "      --default                    Use default settings"
    echo "      --custom                     Use default settings"
    echo "          --path <path>                Specify custom service path"
    echo "          --command <command>          Specify custom persistence command"
    echo "          --timer                      Create systemd timer"
    echo "              --timer-path <path>          Specify custom timer path"
    echo "              --interval <interval>        Specify timer interval"
}

usage_root() {
    echo "Root User Options:"
    echo "  --cron                      Cron job persistence"
    echo "  --shell-configuration       Shell configuration persistence"
    echo "  --ssh-key                   SSH key persistence"
    echo "  --systemd                   Systemd service persistence"
}

# Function for systemd setup
setup_systemd() {
    local default=0
    local service_path=""
    local timer_path=""
    local timer=0
    local interval=""
    local command=""
    local service_name=""
    local custom=0

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
                ;;
            --command )
                shift
                command=$1
                ;;
            --timer )
                timer=1
                ;;
            --timer-path )
                shift
                timer_path=$1
                ;;
            --interval )
                shift
                interval=$1
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
        echo "Using default systemd settings..."
        # Add your default systemd setup code here
        # Example:
        echo "Creating default systemd service..."
        # sudo systemctl start your-default-service
    elif [[ $custom -eq 1 ]]; then
        if [[ -z $service_path || -z $command ]]; then
            echo "Error: --path and --command must be specified when using --custom."
            exit 1
        fi
        echo "Using custom systemd settings..."
        echo "Service path: $service_path"
        echo "Command: $command"
        # Add your custom systemd setup code here
        # Example:
        echo "Creating custom systemd service at $service_path with command $command"
        # Create service file at $service_path and include $command
        if [[ $timer -eq 1 ]]; then
            if [[ -z $timer_path || -z $interval ]]; then
                echo "Error: --timer-path and --interval must be specified when using --timer with --custom."
                exit 1
            fi
            echo "Creating custom systemd timer..."
            echo "Timer path: $timer_path"
            echo "Interval: $interval"
            service_name=$service_path
            # Add your custom systemd timer setup code here
            # Example:
            echo "Creating timer at $timer_path with interval $interval for service $service_name"
            # Create timer file at $timer_path with specified interval
        fi
    else
        echo "Error: Either --default or --custom must be specified for --systemd."
        exit 1
    fi

    echo "Setup completed."

    # Add your systemd setup code here using the variables:
    # $service_path, $command, $timer, $timer_path, $interval

}

# Function for cron job setup
setup_cron() {
    echo "Setting up cron job..."
    # Add your cron setup code here
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
            setup_cron
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