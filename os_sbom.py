import subprocess
import json
import re
import html
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import datetime
import uuid

# Define constants for CVE query API
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"

# Helper function to run shell commands
def run_command(command, capture_output=True, check=False):
    try:
        if capture_output:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check)
            return result.stdout.strip() if result.returncode == 0 else None
        else:
            subprocess.run(command, shell=True, check=check)
    except subprocess.CalledProcessError:
        return None

# Get OS metadata
def get_os_metadata():
    print("Gathering OS metadata...")
    os_name = run_command("lsb_release -ds")
    os_version = run_command("lsb_release -rs")
    architecture = run_command("dpkg --print-architecture")
    kernel_version = run_command("uname -r")

    return {
        "name": os_name,
        "version": os_version,
        "architecture": architecture,
        "kernel_version": kernel_version
    }

# Function to query CVE details
def query_cve_details(cve_id):
    try:
        response = requests.get(CVE_API_URL.format(cve_id), timeout=10)
        if response.status_code == 200:
            return cve_id, response.json()
    except requests.RequestException:
        pass
    return cve_id, None

# Function to parse debsecan output and identify vulnerabilities
def parse_debsecan_output(output):
    print("Parsing debsecan output...")
    packages = defaultdict(lambda: {"version": None, "cves": set()})
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    installed_pattern = re.compile(r"installed: ([\w\-\+\.]+) ([\d\.\+\~\w\-]+)")

    lines = output.splitlines()
    current_package = None

    for line in lines:
        installed_match = installed_pattern.search(line)
        if installed_match:
            package_name = installed_match.group(1)
            version = installed_match.group(2)
            packages[package_name]["version"] = version
            current_package = package_name

        cve_match = cve_pattern.search(line)
        if cve_match and current_package:
            cve_id = cve_match.group(0)
            packages[current_package]["cves"].add(cve_id)

    return packages

# Function to get package dependencies
def get_package_dependencies(package_name):
    dependencies = run_command(f"apt-cache depends {package_name} | grep Depends | cut -d: -f2")
    return [dep.strip() for dep in dependencies.split('\n')] if dependencies else []

def clean_description(text):
    # Unescape HTML entities
    text = html.unescape(text)
    # Remove newline characters
    text = text.replace('\n', ' ')
    # Remove extra spaces
    text = re.sub(r'\s+', ' ', text)
    # Remove any remaining special characters
    text = re.sub(r'[^\x20-\x7E]', '', text)
    return text.strip()

def process_package(package_name, package_info):
    print(f"Processing package: {package_name}")
    dependencies = get_package_dependencies(package_name)

    package_data = {
        "name": package_name,
        "version": package_info["version"],
        "dependencies": dependencies,
        "cves": []
    }

    if package_info["cves"]:
        cves_to_query = list(package_info["cves"])[:3]  # Limit to 3 CVEs
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_cve = {executor.submit(query_cve_details, cve_id): cve_id for cve_id in cves_to_query}
            for future in as_completed(future_to_cve):
                cve_id, cve_details = future.result()
                if cve_details:
                    metrics = cve_details.get("containers", {}).get("cna", {}).get("metrics", [])
                    severity, cvss_score = None, None
                    for metric in metrics:
                        if "cvssV3_1" in metric:
                            cvss_info = metric["cvssV3_1"]
                            severity = cvss_info.get("baseSeverity")
                            cvss_score = cvss_info.get("baseScore")
                            break
                    description = cve_details.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "")
                    cleaned_description = clean_description(description)

                    cve_summary = {
                        "cve_id": cve_id,
                        "description": cleaned_description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                    }
                    package_data["cves"].append(cve_summary)

    return package_data

# Function to install debsecan
def install_debsecan():
    print("Installing debsecan...")
    try:
        # Update package list
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        
        # Install debsecan non-interactively
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        subprocess.run(["sudo", "-E", "apt-get", "install", "-y", "debsecan"], env=env, check=True)
        
        print("debsecan installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install debsecan. Please install it manually and run the script again.")
        sys.exit(1)

def generate_sbom():
    print("Starting SBOM generation...")
    
    # Check if debsecan is installed
    if run_command("which debsecan") is None:
        install_debsecan()
    
    os_metadata = get_os_metadata()

    print("Running debsecan...")
    debsecan_output = run_command("debsecan --suite bookworm --format detail")
    if not debsecan_output:
        print("Failed to get debsecan output.")
        return

    packages = parse_debsecan_output(debsecan_output)

    print("Processing package data...")
    enriched_packages = []
    total_packages = len(packages)
    processed_packages = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_package = {executor.submit(process_package, name, info): name for name, info in packages.items()}
        for future in as_completed(future_to_package):
            package_data = future.result()
            enriched_packages.append(package_data)
            processed_packages += 1
            if processed_packages % 10 == 0:
                print(f"Processed {processed_packages}/{total_packages} packages")

    # Sort packages alphabetically by name
    enriched_packages.sort(key=lambda x: x["name"])

    sbom = {
        "os": os_metadata,
        "packages": enriched_packages
    }

    print("SBOM generated successfully.")

    # Prompt user for uploading or saving locally
    upload_choice = input("Do you want to upload the SBOM to your dashboard? (Y/N): ").strip().upper()
    
    if upload_choice == 'Y':
        email = input("Enter your email: ").strip()
        api_key = input("Enter your API key: ").strip()
        sbom_name = f"LinuxSbom_{datetime.datetime.now().strftime('%Y-%m-%d')}"
        sbom['name'] = sbom_name
        payload = {
            "email": email,
            "apiKey": api_key,
            "sbom": sbom
        }
        url = "http://host.docker.internal:8000/api/auth/linux-sbom"
        print(f"Uploading SBOM '{sbom_name}' to the dashboard...")
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                print("----->> API key verified successfully.")
                print("----->> SBOM uploaded successfully.")
                print(f"Response: {response.json()}")
            else:
                print(f"Failed to upload SBOM. Status Code: {response.status_code}")
                print(f"Response: {response.json()}")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while uploading the SBOM: {e}")
    else:
        # Save locally using UUID
        unique_id = str(uuid.uuid4())
        filename = f"sbom_{unique_id}.json"
        with open(filename, "w") as f:
            json.dump(sbom, f, indent=4)
        print(f"SBOM saved locally as {filename}")

if __name__ == "__main__":
    generate_sbom()
