import os
import pefile
import requests
import json
import time
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
        signature_status, publisher = verify_digital_signature(file_path)
        metadata["Digital_Signature"] = signature_status
        metadata["Publisher"] = publisher
     

        dependencies = []

        # Analyze the import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            functions = [imp.name.decode('utf-8') if imp.name else "Ordinal {}".format(imp.ordinal) for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})

        vulnerabilities = []
        for dependency in dependencies:
            dll_name = dependency["DLL"]
            vulnerability_info = query_nvd_api(dll_name)
            vulnerabilities.append({"DLL": dll_name, "Vulnerabilities": vulnerability_info})

        return {"Metadata": metadata, "Dependencies": dependencies, "Vulnerabilities": vulnerabilities}

    except Exception as e:
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


def query_nvd_api(dll_name):
    vulnerabilities = []
    start_index = 0
    results_per_page = 100  # Number of results per page to get more results in one query

    while len(vulnerabilities) < 20:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={dll_name}&startIndex={start_index}&resultsPerPage={results_per_page}"
            print("Querying NVD API for:", dll_name)
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            current_vulnerabilities = data.get("vulnerabilities", [])

            if not current_vulnerabilities:
                break

            vulnerabilities.extend(current_vulnerabilities)
            start_index += results_per_page

            if len(current_vulnerabilities) < results_per_page:
                break

            time.sleep(1)  # To avoid hitting API rate limits

        except requests.exceptions.RequestException as e:
            print(f"Error querying NVD API for {dll_name}: {e}")
            break

    return vulnerabilities[:20]  # Return at least 20 results

def main():
    exe_path = "mysqlinstaller.msi"  # Specify your local exe file path here
    if not os.path.exists(exe_path):
        print(f"File {exe_path} does not exist.")
        return

    result = analyze_pe_file(exe_path)
    with open("output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("Analysis saved to output.json")

if __name__ == '__main__':
    main()
