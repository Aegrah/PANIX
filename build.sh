#!/bin/bash
# Build PANIX into a single script

OUTPUT_FILE="panix.sh"

# Setup the output file
echo "#!/bin/bash" > "$OUTPUT_FILE"

# Add common module
cat modules/common.sh >> "$OUTPUT_FILE"

# Add all setup modules
for module in modules/setup_*.sh; do
    echo "" >> "$OUTPUT_FILE"
    echo "# Module: $(basename "$module")" >> "$OUTPUT_FILE"
    cat "$module" >> "$OUTPUT_FILE"
done

# Add revert_changes module
echo "" >> "$OUTPUT_FILE"
cat modules/revert_changes.sh >> "$OUTPUT_FILE"

# Add mitre_matrix display module
echo "" >> "$OUTPUT_FILE"
cat modules/display_mitre_matrix.sh >> "$OUTPUT_FILE"

# Exclude the dynamic sourcing block from main.sh
echo "" >> "$OUTPUT_FILE"
echo "# Main script logic" >> "$OUTPUT_FILE"
cat main.sh >> "$OUTPUT_FILE"

# Convert to DOS format
unix2dos "$OUTPUT_FILE"

echo "PANIX combined script created as $OUTPUT_FILE"
