import subprocess
import json
import re
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define constants for CVE query API
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"

# Helper function to run shell commands
def run_command(command):
    try:
        print(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except Exception as e:
        print(f"Error executing command: {e}")
        return None

# Install Debsecan
def install_debsecan():
    print("Checking if Debsecan is installed...")
    if run_command("dpkg -l | grep debsecan") is None:
        print("Debsecan not found. Installing...")
        command = "sudo apt-get install -y debsecan"
        run_command(command)

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
    print(f"Querying CVE details for {cve_id}...")
    response = requests.get(CVE_API_URL.format(cve_id))
    if response.status_code == 200:
        return cve_id, response.json()
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

# Function to process package data
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
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_cve = {executor.submit(query_cve_details, cve_id): cve_id for cve_id in package_info["cves"][:3]}
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
                    description = cve_details.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "").replace("\\r\\n", "").replace("\\n", "").strip()

                    cve_summary = {
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                    }
                    package_data["cves"].append(cve_summary)

    package_data["cves"] = package_data["cves"][:3]
    return package_data

# Main function to generate the SBOM
def generate_sbom():
    print("Starting SBOM generation...")
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
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_package = {executor.submit(process_package, name, info): name for name, info in packages.items()}
        for future in as_completed(future_to_package):
            package_data = future.result()
            enriched_packages.append(package_data)

    # Sort packages alphabetically by name
    enriched_packages.sort(key=lambda x: x["name"])

    sbom = {
        "os": os_metadata,
        "packages": enriched_packages
    }

    print("Writing SBOM to file...")
    with open("sbom_output.json", "w") as f:
        json.dump(sbom, f, indent=4)

    print("SBOM generated successfully and saved as sbom_output.json")

if __name__ == "__main__":
    generate_sbom()
