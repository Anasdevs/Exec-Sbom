import os
import pefile
import requests
import json
import subprocess

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
            functions = [imp.name.decode('utf-8') if imp.name else "Ordinal {}".format(imp.ordinal) for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})
        print("Extracted DLLs and Functions:")

        # Query NVD API for vulnerabilities
        vulnerabilities = []
        for dependency in dependencies:
            dll_name = dependency["DLL"]
            print(f"Querying NVD API for vulnerabilities related to {dll_name}...")
            cve_ids = query_cve_ids_for_dll(dll_name)
            print(f"Found {len(cve_ids)} CVE IDs for {dll_name}")
            for cve_id in cve_ids:
                print(f"Querying CVE info for {cve_id}...")
                cve_info = query_cve_info(cve_id)
                if cve_info:
                    affected_resources = cve_info.get("containers", {}).get("cna", {}).get("affected", [])
                    for resource in affected_resources:
                        if publisher in resource.get("product", ""):
                            vulnerabilities.append({"CVE_ID": cve_id, "CVE_Info": cve_info})
                            print(f"Vulnerability {cve_id} affects the publisher")
                            break
                    else:
                        print(f"Vulnerability {cve_id} does not affect the publisher")
                else:
                    print(f"No CVE info found for {cve_id}")
        
        print("Analysis completed successfully.")
        return {"Metadata": metadata, "Dependencies": dependencies, "Vulnerabilities": vulnerabilities}

    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return {"Error": str(e)}

def verify_digital_signature(file_path):
    try:
        # Run PowerShell command to verify digital signature and retrieve publisher
        ps_command = f"powershell.exe -Command \"& {{$file = '{file_path}'; $signature = Get-AuthenticodeSignature -FilePath $file; if ($signature.Status -eq 'Valid') {{ 'Valid' }} elseif ($signature.Status -eq 'NotSigned') {{ 'NotSigned' }} else {{ 'Invalid' }}; $signature.SignerCertificate.Subject}}\""
        result = subprocess.run(ps_command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(f"PowerShell error: {result.stderr}")
            return "Verification failed", None

        try:
            output_lines = result.stdout.splitlines()
            signature_status = output_lines[0].strip()
            publisher = output_lines[1].strip()
            return signature_status, publisher
        except IndexError:
            print("Error: Signature status or publisher information could not be retrieved.")
            return "Signature cannot be verified", None
        except Exception as e:
            print(f"Error verifying digital signature: {e}")
            return "Signature cannot be verified", None

    except Exception as e:
        print(f"Error verifying digital signature: {e}")
        return "Verification failed", None

def query_cve_ids_for_dll(dll_name):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={dll_name}&startIndex=0&resultsPerPage=50"
        print(url)
        response = requests.get(url)
        # print(response.json())
        response.raise_for_status()
        data = response.json()
        cve_entries = data.get("result", {}).get("CVE_Items", [])
        cve_ids = [entry.get("cve", {}).get("CVE_data_meta", {}).get("ID") for entry in cve_entries]
        return cve_ids
    except Exception as e:
        print(f"Error querying NVD API for CVE IDs: {e}")
        return []

def query_cve_info(cve_id):
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url)
        response.raise_for_status()
        cve_info = response.json()
        return cve_info
    except Exception as e:
        print(f"Error querying CVE info for {cve_id}: {e}")
        return {}

def main():
    exe_path = "ChromeSetup.exe"  # Specify your local exe file path here
    if not os.path.exists(exe_path):
        print(f"File {exe_path} does not exist.")
        return

    result = analyze_pe_file(exe_path)
    with open("output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("Analysis saved to output.json")

if __name__ == '__main__':
    main()
