import pandas as pd
import re
import datetime
import os
from typing import Tuple, Set, List
import random

def read_file(file_path):
    # Check if the file exists
    while not os.path.exists(file_path):
        print(f"File does not exist: {file_path}")
        file_path = input("Please enter a valid file path: ")  # Ask user to re-enter the file path

    if file_path.endswith('.xls') or file_path.endswith('.xlsx'):
        return pd.read_excel(file_path)
    elif file_path.endswith('.txt'):
        with open(file_path, 'r') as file:
            return file.read()  # Read the entire file content as a single string
    else:
        raise ValueError("Unsupported file format. Please provide a .txt or .xls file.")

def clean_value(value: str) -> str:
    """Replace '[.]' with '.' in a given value."""
    return value.replace("[.]", ".")

# Function to identify IPs, Domains and Hashes
def extract_ips_hashes_domains(data: str) -> Tuple[Set[str], Set[str], Set[str], Set[str], Set[str], Set[str]]:
    ipv4_regex = r'\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b'  # Match IPv4 with [.] or .
    ipv6_regex = r'\b([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}\b'  # Match standard IPv6
    md5_regex = r'\b[a-f0-9]{32}\b'  # Match MD5
    sha1_regex = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)  # Match SHA1 with case insensitivity
    sha256_regex = r'\b[a-f0-9]{64}\b'  # Match SHA256
    domain_regex = r'\b(?:[a-zA-Z0-9-]+\[?\.\]?)+[a-zA-Z]{2,}\b'  # Match domains with [.] or .

    # Apply regex and clean '[.]' to '.'
    ipv4 = {clean_value(ip) for ip in re.findall(ipv4_regex, data)}
    ipv6 = {clean_value(ip) for ip in re.findall(ipv6_regex, data)}
    md5 = {clean_value(hash) for hash in re.findall(md5_regex, data)}
    sha1 = {clean_value(hash) for hash in sha1_regex.findall(data)}
    sha256 = {clean_value(hash) for hash in re.findall(sha256_regex, data)}
    domains = {clean_value(domain) for domain in re.findall(domain_regex, data)}

    return ipv4, ipv6, md5, sha1, sha256, domains

def append_to_csv(filename: str, data: Set[str], data_type: str, malware_family: str, apt_group: str) -> None:
    if not data:  # Skip if the data set is empty
        return

    # Ensure the output directory exists
    output_folder = "CREATED_IOCs"
    os.makedirs(output_folder, exist_ok=True)

    # Define the path for the CSV file
    file_path = os.path.join(output_folder, f"{filename}.csv")

    # Define the structure of the DataFrame
    columns = ["Value", "Type", "malware_families","kill_chains", "severity", "APT_group",  "Additional Info"]
    new_data = pd.DataFrame(
        [
            [value, data_type, f'"{malware_family.strip()}"', "<kill chain>", "", f'"{apt_group.strip()}"', ""]
            for value in data
        ],
        columns=columns,
    )

    # If the file does not exist, create it with headers
    if not os.path.exists(file_path):
        new_data.to_csv(file_path, index=False)
    else:
        # Read existing data to prevent duplicate entries
        existing_data = pd.read_csv(file_path)
        combined_data = pd.concat([existing_data, new_data]).drop_duplicates(subset="Value")
        combined_data.to_csv(file_path, index=False)

        
def generate_suricata_ip_rule(ip: str, apt_group: str) -> str:
    sid = random.randint(100000000, 9999999999)
    # Rule for IP as the source (sending)
    sending_rule = f'alert ip {ip} any -> any any (msg:"Suspicious {base_filename} IP detected Entering Network: {ip} (source) - APT Group: {apt_group}"; sid:{sid}; rev:1;)\n'
    # Rule for IP as the destination (receiving)
    receiving_rule = f'alert ip any any -> {ip} any (msg:"Suspicious {base_filename} IP detected Leaving Network: {ip} (destination) - APT Group: {apt_group}"; sid:{sid + 1}; rev:1;)\n'

    return sending_rule + receiving_rule

def generate_yara_rule(ips, md5_hashes, sha1_hashes, sha256_hashes, domains, creator_name, apt_group):
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")

    rule = f'{base_filename}_IOCs {{\n'
    rule += '  meta:\n'
    rule += f'    creator = "{creator_name}"\n'
    rule += f'    date = "{current_date}"\n'
    rule += f'    description = "Suspicious IPs, Hashes, and Domains"\n'
    rule += f'    apt_group = "{apt_group}"\n'

    rule += '  strings:\n'
    for ip in ips:
        rule += f'    $ip_{ip.replace(".", "_")} = "{ip}"\n'
    for md5 in md5_hashes:
        rule += f'    $md5_{md5} = "{md5}"\n'
    for sha1 in sha1_hashes:
        rule += f'    $sha1_{sha1} = "{sha1}"\n'
    for sha256 in sha256_hashes:
        rule += f'    $sha256_{sha256[:8]} = "{sha256}"\n'
    for domain in domains:
        rule += f'    $domain_{domain.replace(".", "_")} = "{domain}"\n'

    rule += '  condition:\n'
    rule += '    any of them\n'
    rule += '}\n'

    return rule

def generate_rules_from_file(file_path: str, base_filename: str, creator_name: str) -> None:
    data = read_file(file_path)
    ip, ipv6, md5, sha1, sha256, domain = extract_ips_hashes_domains(data)

    malware_family = input("Malware family? (or press Enter to skip): ")
    apt_group = input("APT group? (or press Enter to skip): ")

    append_to_csv("md5", md5, "md5", malware_family, apt_group)
    append_to_csv("sha1", sha1, "sha1", malware_family, apt_group)
    append_to_csv("sha256", sha256, "sha256", malware_family, apt_group)
    append_to_csv("ip", ip, "IPv4", malware_family, apt_group)
    append_to_csv("ipv6", ipv6, "IPv6", malware_family, apt_group)
    append_to_csv("domains", domain, "domain", malware_family, apt_group)

    suricata_rules: List[str] = [generate_suricata_ip_rule(ip, apt_group) for ip in ip]

    current_date = datetime.datetime.now().strftime("%Y%m%d")
    suricata_filename = f"{base_filename}-suricata-{current_date}.txt"
    yara_filename = f"{base_filename}-yara-{current_date}.yar"

    output_folder = "CREATED_IOCs"
    os.makedirs(output_folder, exist_ok=True)

    suricata_file_path = os.path.join(output_folder, suricata_filename)
    yara_file_path = os.path.join(output_folder, yara_filename)

    with open(suricata_file_path, "w") as suricata_file:
        suricata_file.writelines(suricata_rules)

    yara_rule = generate_yara_rule(ip, md5, sha1, sha256, domain, creator_name, apt_group)
    with open(yara_file_path, "w") as yara_file:
        yara_file.write(yara_rule)

    print(f"Suricata rules saved to: {suricata_file_path}")
    print(f"YARA rules saved to: {yara_file_path}")

# Example usage:
creator_name = input("Enter your name: ")
file_path = input("Enter the path to your file: ")
base_filename = input("Enter the base filename for the output: ")

generate_rules_from_file(file_path, base_filename, creator_name)
