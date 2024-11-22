#!/bin/bash
# Build PANIX into a single script with interleaved setup and revert modules

OUTPUT_FILE="panix.sh"

# Setup the output file
echo "#!/bin/bash" > "$OUTPUT_FILE"

# Add common module
cat modules/common.sh >> "$OUTPUT_FILE"

# Add interleaved setup and revert modules
for setup_module in modules/setup_*.sh; do
	# Add the setup module
	echo "" >> "$OUTPUT_FILE"
	echo "# Module: $(basename "$setup_module")" >> "$OUTPUT_FILE"
	cat "$setup_module" >> "$OUTPUT_FILE"

	# Determine the corresponding revert module
	module_name=$(basename "$setup_module" | sed 's/setup_/revert_/')
	revert_module="modules/revert/$module_name"

	# Add the revert module if it exists
	if [[ -f "$revert_module" ]]; then
		echo "" >> "$OUTPUT_FILE"
		echo "# Revert Module: $(basename "$revert_module")" >> "$OUTPUT_FILE"
		cat "$revert_module" >> "$OUTPUT_FILE"
	else
		echo "" >> "$OUTPUT_FILE"
		echo "# Revert Module: Missing for $(basename "$setup_module")" >> "$OUTPUT_FILE"
	fi
done

# Add mitre_matrix display module
echo "" >> "$OUTPUT_FILE"
cat modules/display_mitre_matrix.sh >> "$OUTPUT_FILE"

# Exclude the dynamic sourcing block from main.sh
echo "" >> "$OUTPUT_FILE"
echo "# Main script logic" >> "$OUTPUT_FILE"
cat main.sh >> "$OUTPUT_FILE"

# Ensure proper line endings
dos2unix panix.sh

echo "PANIX combined script created as $OUTPUT_FILE"
