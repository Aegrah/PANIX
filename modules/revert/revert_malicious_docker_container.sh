revert_malicious_container() {
	usage_revert_malicious_container() {
		echo "Usage: ./panix.sh --revert malicious-container"
		echo "Reverts any changes made by the setup_malicious_docker_container module."
	}

	# Check if Docker is available
	if ! docker ps &> /dev/null; then
		echo "Error: Docker daemon is not running or permission denied."
		return 1
	fi

	# Stop and remove the malicious container
	if docker ps -a --format '{{.Names}}' | grep -q '^malicious-container$'; then
		echo "[+] Stopping and removing the 'malicious-container'..."
		docker stop malicious-container >/dev/null 2>&1
		docker rm malicious-container >/dev/null 2>&1
		echo "[+] Container 'malicious-container' stopped and removed."
	else
		echo "[-] Container 'malicious-container' not found. No action needed."
	fi

	# Remove the Docker image
	if docker images -q malicious-container > /dev/null 2>&1; then
		echo "[+] Removing Docker image 'malicious-container'..."
		docker rmi malicious-container -f >/dev/null 2>&1
		echo "[+] Docker image 'malicious-container' removed."
	else
		echo "[-] Docker image 'malicious-container' not found. No action needed."
	fi

	# Remove the Dockerfile
	DOCKERFILE="/tmp/Dockerfile"
	if [[ -f "$DOCKERFILE" ]]; then
		echo "[+] Removing Dockerfile at $DOCKERFILE..."
		rm -f "$DOCKERFILE"
		echo "[+] Dockerfile removed."
	else
		echo "[-] Dockerfile at $DOCKERFILE not found. No action needed."
	fi

	return 0
}
