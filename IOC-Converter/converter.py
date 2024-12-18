import pandas as pd
import re
import datetime
import os

def read_file(file_path):
    # Check if the file exists
    while not os.path.exists(file_path):
        print(f"File does not exist: {file_path}")
        file_path = input("Please enter a valid file path: ")  # Ask user to re-enter the file path

    if file_path.endswith('.xls') or file_path.endswith('.xlsx'):
        return pd.read_excel(file_path)
    elif file_path.endswith('.txt'):
        with open(file_path, 'r') as file:
            return file.readlines()
    else:
        raise ValueError("Unsupported file format. Please provide a .txt or .xls file.")

# Function to identify IPs and Hashes
def extract_ips_and_hashes(data):
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    md5_regex = r'\b[a-f0-9]{32}\b'
    sha256_regex = r'\b[a-f0-9]{64}\b'
    
    ips = set(re.findall(ip_regex, str(data)))
    md5_hashes = set(re.findall(md5_regex, str(data)))
    sha256_hashes = set(re.findall(sha256_regex, str(data)))
    
    return ips, md5_hashes, sha256_hashes

# Function to generate Suricata rules for IPs
def generate_suricata_ip_rule(ip):
    return f"alert ip {ip} any -> any any (msg:\"Suspicious IP detected: {ip}\"; sid:1000001;)\n"

# Function to generate a single consolidated YARA rule for IPs and Hashes
def generate_yara_rule(ips, md5_hashes, sha256_hashes):
    rule = "rule suspicious_IOCs {\n"
    rule += "  meta:\n"
    rule += "    description = \"Suspicious IPs and Hashes\"\n"

    rule += "  strings:\n"
    # Add IPs to the YARA rule
    for ip in ips:
        rule += f"    $ip_{ip.replace('.', '_')} = \"{ip}\"\n"
    
    # Add MD5 hashes to the YARA rule
    for md5 in md5_hashes:
        rule += f"    $md5_{md5} = \"{md5}\"\n"
    
    # Add SHA256 hashes to the YARA rule
    for sha256 in sha256_hashes:
        rule += f"    $sha256_{sha256[:8]} = \"{sha256}\"\n"

    rule += "  condition:\n"
    rule += "    any of ($ip*) or any of ($md5*) or any of ($sha256*)\n"
    rule += "}\n"

    return rule

# Main function to process file and generate rules
def generate_rules_from_file(file_path, base_filename):
    data = read_file(file_path)
    ips, md5_hashes, sha256_hashes = extract_ips_and_hashes(data)
    
    suricata_rules = []
    
    # Generate Suricata rules for IPs
    for ip in ips:
        suricata_rules.append(generate_suricata_ip_rule(ip))
    
    # Get the current date for file naming
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    
    # Define filenames with the current date and base filename
    suricata_filename = f"{base_filename}-suricata-{current_date}.txt"
    yara_filename = f"{base_filename}-yara-{current_date}.yar"
    
    # Create the 'CREATED_IOCs' folder if it doesn't exist
    output_folder = "CREATED_IOCs"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    # Define the full paths to save the files in the 'CREATED_IOCs' folder
    suricata_file_path = os.path.join(output_folder, suricata_filename)
    yara_file_path = os.path.join(output_folder, yara_filename)
    
    # Save Suricata rules to a .txt file
    with open(suricata_file_path, "w") as suricata_file:
        suricata_file.writelines(suricata_rules)
    
    # Generate a single YARA rule
    yara_rule = generate_yara_rule(ips, md5_hashes, sha256_hashes)
    
    # Save the YARA rule to a .yar file
    with open(yara_file_path, "w") as yara_file:
        yara_file.write(yara_rule)
    
    print(f"Suricata rules saved to: {suricata_file_path}")
    print(f"YARA rules saved to: {yara_file_path}")

# Example usage:
file_path = input("Enter the path to your file: ")  # e.g., path_to_your_file.txt or path_to_your_file.xlsx
base_filename = input("Enter the base filename for the output: ")  # e.g., "Magic Hound"

generate_rules_from_file(file_path, base_filename)
