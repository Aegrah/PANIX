revert_at() {
	usage_revert_at() {
		echo "Usage: ./panix.sh --revert at"
		echo "Reverts any changes made by the setup_at module."
	}

	if ! command -v at &> /dev/null; then
		echo "Error: 'at' binary is not present. Cannot revert 'at' jobs."
		return 1
	fi

	# Fetch all queued `at` jobs
	jobs=$(atq | awk '{print $1}')
	if [[ -z "$jobs" ]]; then
		echo "[-] No 'at' jobs found to revert."
		return 0
	fi

	# Iterate over each job, check its command, and remove if it matches known patterns
	for job in $jobs; do
		job_info=$(at -c "$job")
		if [[ "$job_info" =~ "sh -i >& /dev/tcp" || "$job_info" =~ "/bin/bash -c" ]]; then
			atrm "$job"
			echo "[+] Removed matching 'at' job with ID $job."
		fi
	done

    return 0
}
