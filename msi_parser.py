import os
import json
import subprocess
import msilib

def analyze_msi_file(file_path):
    try:
        # Extract metadata from the MSI file
        metadata = {}
        db = msilib.OpenDatabase(file_path, msilib.MSIDBOPEN_READONLY)
        view = db.OpenView("SELECT * FROM Property")
        view.Execute(None)
        while True:
            rec = view.Fetch()
            if not rec:
                break
            metadata[rec.GetString(1)] = rec.GetString(2)

        return {"Metadata": metadata, "Dependencies": [], "Vulnerabilities": []}

    except Exception as e:
        return {"Error": str(e)}

def main():
    msi_path = "mysqlinstaller.msi"
    if not os.path.exists(msi_path):
        print(f"File {msi_path} does not exist.")
        return

    result = analyze_msi_file(msi_path)
    with open("output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("Analysis saved to output.json")

if __name__ == '__main__':
    main()
