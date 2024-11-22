revert_password_change() {

	echo "[!] Function setup_password_change does not have a revert function."
	return 1

	usage_revert_password_change() {
		echo "Usage: ./panix.sh --revert password-change"
		echo "Reverts any changes made by the setup_password_change module."
	}
}
