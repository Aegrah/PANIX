revert_git() {
	usage_revert_git() {
		echo "Usage: ./panix.sh --revert git"
		echo "Reverts any changes made by the setup_git_persistence module."
	}

	# Function to remove malicious pre-commit hooks
	remove_malicious_pre_commit() {
		local git_repo="$1"
		local pre_commit_file="$git_repo/.git/hooks/pre-commit"

		if [[ -f $pre_commit_file ]]; then
			# Check if the pre-commit hook contains the malicious payload
			if grep -q "nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/" "$pre_commit_file"; then
				rm -f "$pre_commit_file"
				echo "[+] Removed malicious pre-commit hook from $git_repo"
			else
				echo "[-] Pre-commit hook in $git_repo does not contain the malicious payload. Skipping."
			fi
		else
			echo "[-] No pre-commit hook found in $git_repo. Skipping."
		fi
	}

	# Function to remove malicious pager configurations
	remove_malicious_pager() {
		local config_file="$1"

		if [[ -f $config_file ]]; then
			# Check if the config contains the malicious pager
			if grep -q "nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/" "$config_file"; then
				# Remove the malicious pager line
				sed -i "/pager = nohup setsid \/bin\/bash -c 'bash -i >& \/dev\/tcp\/.*\/.* 0>&1' > \/dev\/null 2>&1 & \\\${PAGER:-less}/d" "$config_file"
				echo "[+] Removed malicious pager configuration from $config_file"
			else
				echo "[-] No malicious pager configuration found in $config_file. Skipping."
			fi
		else
			echo "[-] Config file $config_file does not exist. Skipping."
		fi
	}

	# Function to find Git repositories and remove persistence
	find_git_repositories_and_revert() {
		local repos
		repos=$(find / -type d -name ".git" 2>/dev/null)

		if [[ -z $repos ]]; then
			echo "[-] No Git repositories found."
		else
			for repo in $repos; do
				local git_repo
				git_repo=$(dirname "$repo")
				remove_malicious_pre_commit "$git_repo"

				local git_config="$git_repo/.git/config"
				remove_malicious_pager "$git_config"
			done
		fi
	}

	# Remove malicious pager from user's global Git config
	remove_malicious_pager_global() {
		local user_git_config="$HOME/.gitconfig"
		remove_malicious_pager "$user_git_config"
	}

	# Execute the revert functions
	find_git_repositories_and_revert
	remove_malicious_pager_global

	return 0
}
