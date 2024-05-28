import os
import pefile
import requests
import json
import subprocess
import re

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)

        metadata = {
            "Signature": hex(pe.DOS_HEADER.e_magic),
            "Machine": pe.FILE_HEADER.Machine,
            "Number_of_Sections": pe.FILE_HEADER.NumberOfSections,
            "Time_Date_Stamp": pe.FILE_HEADER.TimeDateStamp,
            "Entry_Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image_Base": hex(pe.OPTIONAL_HEADER.ImageBase)
        }

        # Verify digital signature
        print("Verifying digital signature...")
        signature_status, publisher = verify_digital_signature(file_path)
        metadata["Digital_Signature"] = signature_status
        metadata["Publisher"] = publisher
        print(f"Digital Signature Status: {signature_status}")
        print(f"Publisher: {publisher}")

        # Get DLLs and functions
        dependencies = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            functions = [imp.name.decode('utf-8') if imp.name else f"Ordinal {imp.ordinal}" for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})
        print("Extracted DLLs and Functions:")

        # Query NVD API for vulnerabilities and find matching functions
        for dependency in dependencies:
            dll_name = dependency["DLL"]
            print(f"Querying NVD API for vulnerabilities related to {dll_name}...")
            cve_items = query_cve_items_for_dll(dll_name)
            print(f"Found {len(cve_items)} CVE items for {dll_name}")
            vulnerabilities = []
            for cve_item in cve_items:
                cve_id = cve_item.get("cve", {}).get("id")
                description = cve_item.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                matched_functions = find_matching_functions(description, dependency["Functions"])
                vulnerabilities.append({
                    "CVE_ID": cve_id,
                    "Description": description,
                    "Matched_Functions": matched_functions
                })
            dependency["Vulnerabilities"] = vulnerabilities

        print("Analysis completed successfully.")
        return {"Metadata": metadata, "Dependencies": dependencies}

    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return {"Error": str(e)}

def verify_digital_signature(file_path):
    try:
        ps_command = f"powershell.exe -Command \"& {{$file = '{file_path}'; $signature = Get-AuthenticodeSignature -FilePath $file; if ($signature.Status -eq 'Valid') {{ 'Valid' }} elseif ($signature.Status -eq 'NotSigned') {{ 'NotSigned' }} else {{ 'Invalid' }}; $signature.SignerCertificate.Subject}}\""
        result = subprocess.run(ps_command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(f"PowerShell error: {result.stderr}")
            return "Verification failed", None

        output_lines = result.stdout.splitlines()
        signature_status = output_lines[0].strip()
        publisher = output_lines[1].strip()
        return signature_status, publisher

    except Exception as e:
        print(f"Error verifying digital signature: {e}")
        return "Verification failed", None

def query_cve_items_for_dll(dll_name):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={dll_name}&keywordExactMatch"
        print(f"URL IS: {url}")
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error querying NVD API for DLL {dll_name}: {e}")
        return []

def find_matching_functions(description, functions):
    try:
        matched_functions = []
        description = description.lower()
        for func in functions:
            if re.search(r'\b' + re.escape(func.lower()) + r'\b', description):
                matched_functions.append(func)
        return matched_functions
    except Exception as e:
        print(f"Error finding matching functions: {e}")
        return []

def main():
    exe_path = "CleanupInst.exe"  # Specify your local exe file path here
    if not os.path.exists(exe_path):
        print(f"File {exe_path} does not exist.")
        return

    result = analyze_pe_file(exe_path)
    with open("output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("Analysis saved to output.json")

if __name__ == '__main__':
    main()
