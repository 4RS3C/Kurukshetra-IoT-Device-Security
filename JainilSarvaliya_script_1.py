import os
import hashlib
import binwalk
import re
import subprocess
import numpy as np
from collections import Counter
import math
import time
import chardet
import pwd
import grp
from datetime import datetime

# First Script Functions
# File size function
def get_file_size(file_path):
    return os.path.getsize(file_path)

# MD5 hash function
def get_md5_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# File format detection
def get_file_format(file_path):
    with open(file_path, "rb") as f:
        header = f.read(4)
    if header[:4] == b"\x7fELF":
        return "ELF"
    elif header[:2] == b"MZ":
        return "PE"
    return "BIN"

# URL extraction function
def find_urls(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    urls = re.findall(r'(https?://[^\s]+)', data.decode(errors='ignore'))
    return list(set(urls))

# IP address extraction function
def find_ip_addresses(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', data.decode(errors='ignore'))
    return list(set(ips))

# Binwalk extraction for packing info
def get_packing_info(file_path):
    binwalk_output = subprocess.run(['binwalk', '--extract', file_path], capture_output=True, text=True)
    return binwalk_output.stdout

# Custom entropy calculation
def calculate_entropy(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    byte_counts = Counter(data)
    total_bytes = len(data)
    entropy = 0
    for count in byte_counts.values():
        prob = count / total_bytes
        entropy -= prob * math.log2(prob)
    return entropy

# Entropy analysis
def analyze_entropy(file_path):
    entropy_value = calculate_entropy(file_path)
    analysis = 'Packed' if entropy_value > 7.5 else 'Unpacked'
    return analysis

# File metadata retrieval using 'file' command
def get_file_metadata(file_path):
    try:
        file_output = subprocess.check_output(['file', file_path]).decode(errors='ignore')
        return file_output.strip()  # Return the output as a string
    except subprocess.CalledProcessError as e:
        return f"Error retrieving metadata: {e}"

# Architecture extraction based on file command output
def extract_architecture(metadata):
    arch_patterns = [
        r'ELF.*?x86_64',
        r'ELF.*?i386',
        r'ELF.*?arm',
        r'ELF.*?aarch64',
        r'Linux/ARM',
        r'Linux/i386',
        r'Linux/x86_64'
    ]
    for pattern in arch_patterns:
        match = re.search(pattern, metadata)
        if match:
            return match.group(0)
    return "Unknown Architecture"

# UI resources detection based on strings
def get_ui_resources(file_path):
    ui_resources = []
    with open(file_path, 'rb') as f:
        strings = subprocess.check_output(['strings', file_path]).decode(errors='ignore')
    ui_resources = re.findall(r'(button|icon|image|logo|text)', strings)
    return list(set(ui_resources))

# Cryptographic algorithm detection
def get_cryptographic_algorithms(file_path):
    cryptographic_algorithms = []
    with open(file_path, 'rb') as f:
        data = f.read()
    if b'AES' in data:
        cryptographic_algorithms.append('AES')
    if b'RSA' in data:
        cryptographic_algorithms.append('RSA')
    if b'ARC4' in data:
        cryptographic_algorithms.append('ARC4')
    return cryptographic_algorithms

# Top 10 potential password detection based on strings
def get_top_10_passwords(file_path):
    passwords = []
    with open(file_path, 'rb') as f:
        strings = subprocess.check_output(['strings', file_path]).decode(errors='ignore')
    passwords = re.findall(r'(\w{6,})', strings)
    return [item[0] for item in Counter(passwords).most_common(10)]

# Run a shell command and return the result
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

# Extract firmware binary file using binwalk
def extract_bin_file(bin_file_path, extract_path):
    print(f"Extracting {bin_file_path} to {extract_path}...")
    try:
        binwalk_command = f"binwalk --extract --directory \"{extract_path}\" \"{bin_file_path}\""
        subprocess.run(binwalk_command, shell=True, check=True)
        print(f"Extraction completed to {extract_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error during extraction: {e}")
        return False
    return True

# Process extracted files and gather information (second part)
def process_extracted_files(extracted_dir):
    # Lists for storing extracted information
    ssl_files, config_files, script_files, bin_files, urls, emails, ip_addresses = [], [], [], [], [], [], []

    # Walk through the extracted directory
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            file_path = os.path.join(root, file)

            with open(file_path, 'rb') as f:
                try:
                    data = f.read().decode(errors='ignore')
                except UnicodeDecodeError:
                    continue

            # Detect SSL files
            if file.endswith(('.pem', '.crt', '.key')):
                ssl_files.append(file_path)

            # Detect configuration files
            if any(pattern in file for pattern in ['config', 'settings', 'config.txt', 'config.json', 'config.yaml', '.conf']):
                config_files.append(file_path)

            # Detect script files
            if file.endswith(('.sh', '.py', '.pl', '.cgi')):
                script_files.append(file_path)

            # Collect URLs, emails, and IPs
            urls += re.findall(r'https?://[^\s]+', data)
            emails += re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)
            ip_matches = re.findall(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)|(\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)', data)
            for match in ip_matches:
                ip_address = match[0] if match[0] else match[2]
                if ip_address:
                    ip_addresses.append(ip_address)

    return ssl_files, config_files, script_files, bin_files, list(set(urls)), list(set(emails)), list(set(ip_addresses))

# Write both analysis outputs to a single file
def write_output_to_file(output_file, file_info, ssl_files, config_files, script_files, bin_files, urls, emails, ip_addresses):
    with open(output_file, 'w') as f:
        for key, value in file_info.items():
            f.write(f"{key}: {value}\n\n")
        
        f.write("\nExtracted Information:\n")
        f.write("\nSSL files:\n")
        if ssl_files:
            f.write("\n".join(ssl_files) + "\n")
        else:
            f.write("No SSL files found.\n")

        f.write("\nConfiguration files:\n")
        if config_files:
            f.write("\n".join(config_files) + "\n")
        else:
            f.write("No configuration files found.\n")

        f.write("\nScript files:\n")
        if script_files:
            f.write("\n".join(script_files) + "\n")
        else:
            f.write("No script files found.\n")

        f.write("\nOther .bin files:\n")
        if bin_files:
            f.write("\n".join(bin_files) + "\n")
        else:
            f.write("No .bin files found.\n")

        f.write("\nURLs, Emails, and IP addresses found:\n")
        if urls or emails or ip_addresses:
            if urls:
                f.write("URLs: " + ", ".join(urls) + "\n")
            if emails:
                f.write("Emails: " + ", ".join(emails) + "\n")
            if ip_addresses:
                f.write("IP addresses: " + ", ".join(ip_addresses) + "\n")
        else:
            f.write("No URLs, emails, or IP addresses found.\n")

# Extract firmware binary file using binwalk
def extract_firmware(firmware_path):
    # Extract firmware using binwalk
    if not os.path.isfile(firmware_path):
        print(f"Error: The file {firmware_path} does not exist.")
        return None
    
    # Create a directory to extract the firmware content
    extract_dir = f"{firmware_path}_extracted"
    if os.path.exists(extract_dir):
        print(f"Warning: Extracted directory {extract_dir} already exists.")
    else:
        os.makedirs(extract_dir)
    
    # Run binwalk extraction command
    print(f"Extracting firmware from {firmware_path}...")
    try:
        subprocess.run(["binwalk", "-e", "-C", extract_dir, firmware_path], check=True)
        print("Extraction complete.")
    except subprocess.CalledProcessError:
        print(f"Error: Failed to extract {firmware_path}. Please ensure binwalk is installed.")
        return None

    return extract_dir

# Generate the file structure tree using the 'tree' command
def generate_file_tree(extracted_dir):
    print("Generating file structure tree...")
    try:
        result = subprocess.run(["tree", "-L", "2", extracted_dir], capture_output=True, text=True, check=True)
        tree_output = result.stdout
    except subprocess.CalledProcessError:
        print("Error generating the file tree.")
        return None

    return tree_output

# Analyzing files accessed: get file stats (created/modified time)
def analyze_files_accessed(extracted_dir):
    print("Analyzing file access times...")
    file_info = []
    for root, dirs, files in os.walk(extracted_dir):
        for file in files:
            file_path = os.path.join(root, file)
            stat = os.stat(file_path)
            created_time = time.ctime(stat.st_ctime)
            modified_time = time.ctime(stat.st_mtime)
            file_info.append(f"{file_path}: Created - {created_time}, Modified - {modified_time}")
    
    return file_info

# Save analysis to a markdown file
def save_to_markdown(file_tree, accessed_files_info, output_file):
    print(f"Saving output to {output_file}...")
    with open(output_file, "w") as md_file:
        md_file.write("# Firmware Analysis Report\n\n")
        
        # File tree section
        md_file.write(f"## File Structure\n\n")
        md_file.write("```\n")
        md_file.write(file_tree)  # Insert the tree structure here
        md_file.write("```\n\n")
        
        # Files accessed section
        md_file.write(f"## Files Accessed\n\n")
        for file_info in accessed_files_info:
            md_file.write(f"- {file_info}\n")
    
    print(f"Output saved to {output_file}.")

# Main function
def main():
    firmware_file = input("Please enter the full path to the firmware binary file: ").strip()

    # Collect basic file info
    file_info = {}
    file_info['File Size'] = get_file_size(firmware_file)
    file_info['MD5 Hash'] = get_md5_hash(firmware_file)
    file_info['File Format'] = get_file_format(firmware_file)
    file_info['Packing'] = get_packing_info(firmware_file)
    file_info['Entropy'] = calculate_entropy(firmware_file)
    file_info['Entropy Analysis'] = analyze_entropy(firmware_file)
    metadata = get_file_metadata(firmware_file)
    file_info['File Metadata'] = metadata
    file_info['Architecture'] = extract_architecture(metadata)

    # Extract firmware
    extract_path = os.path.splitext(firmware_file)[0] + "-extracted"
    if not extract_bin_file(firmware_file, extract_path):
        return

    # Process files in the extracted directory
    ssl_files, config_files, script_files, bin_files, urls, emails, ip_addresses = process_extracted_files(extract_path)

    # Write the output to a single file
    output_file = os.path.join(os.path.dirname(firmware_file), "firmware_analysis_report.txt")
    write_output_to_file(output_file, file_info, ssl_files, config_files, script_files, bin_files, urls, emails, ip_addresses)

    # Additional analysis
    extracted_dir = extract_firmware(firmware_file)
    if extracted_dir:
        file_tree = generate_file_tree(extracted_dir)
        accessed_files_info = analyze_files_accessed(extracted_dir)
        
        # Generate output markdown file
        output_md_file = "filesystem.md"  # Changed output file name
        save_to_markdown(file_tree, accessed_files_info, output_md_file)

    print(f"Analysis complete. Report written to {output_file}")

if __name__ == '__main__':
    main()
