#!/bin/bash
# Script to generate SHA256SUMS.txt for compiled Linux packages.
# Run this script inside the release/v1.4.0/linux/ directory after putting the packages here.

cd "$(dirname "$0")"

echo "Generating SHA256SUMS.txt..."
rm -f SHA256SUMS.txt

# Find deb, AppImage, and tar.gz files
files=$(ls | grep -E '\.(deb|AppImage|tar\.gz)$')

if [ -z "$files" ]; then
    echo "Warning: No package files (.deb, .AppImage, .tar.gz) found in this directory."
    echo "Please copy the compiled packages into this directory first."
    exit 1
fi

for f in $files; do
    sha256sum "$f" >> SHA256SUMS.txt
done

echo "Done. Contents of SHA256SUMS.txt:"
cat SHA256SUMS.txt
