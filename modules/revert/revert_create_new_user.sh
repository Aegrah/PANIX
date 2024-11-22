revert_create_user() {

	echo "[!] Function setup_create_new_user does not have a revert function."
	return 1

	usage_revert_create_user() {
		echo "Usage: ./panix.sh --revert create-user"
		echo "Reverts any changes made by the setup_create_new_user module."
	}
}