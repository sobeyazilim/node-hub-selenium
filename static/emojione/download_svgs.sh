#!/bin/bash
# ./download_svgs.sh svglist ./2.0.1
# Check if the correct number of arguments is passed
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_file> <output_directory>"
    exit 1
fi

# Input file containing URLs (one per line)
input_file=$1

# Output directory where the SVGs will be saved
output_dir=$2

# Check if the input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found!"
    exit 1
fi

# Check if the output directory exists, if not create it
if [ ! -d "$output_dir" ]; then
    echo "Output directory '$output_dir' does not exist. Creating it..."
    mkdir -p "$output_dir"
fi

# Read each line in the input file (each line should be a URL)
while IFS= read -r url; do
    # Skip empty lines or lines that start with #
    if [ -z "$url" ] || [[ "$url" =~ ^# ]]; then
        continue
    fi

    # Get the filename from the URL (extract the base filename from the URL)
    filename=$(basename "$url")

    # Download the SVG file using wget
    echo "Downloading $url as $filename..."
    wget -q "$url" -O "$output_dir/$filename"

    # Check if wget was successful
    if [ $? -eq 0 ]; then
        echo "Successfully downloaded: $filename"
    else
        echo "Failed to download: $filename"
    fi

done < "$input_file"

echo "Download process completed."
