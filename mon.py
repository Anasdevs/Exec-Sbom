import pefile

def analyze_pe_file(file_name):
  """Analyzes a PE file and stores the information in a text file.

  Args:
      file_name: Name of the PE file to analyze.
  """
  try:
    # Open the PE file
    pe = pefile.PE(file_name)

    # Open output file for writing
    with open("output.txt", "w") as f:
      f.write(f"PE File Analysis Results: {file_name}\n")

      # General information
      f.write(f"\tMachine: {pe.FILE_HEADER.Machine}\n")
      f.write(f"\tSize of Image: {pe.OPTIONAL_HEADER.SizeOfImage}\n")
      f.write(f"\tMajor Linker Version: {pe.OPTIONAL_HEADER.MajorLinkerVersion}\n")
      f.write(f"\tMinor Linker Version: {pe.OPTIONAL_HEADER.MinorLinkerVersion}\n")

      # Import information
      f.write("\n\tImported Libraries:\n")
      for entry in pe.DIRECTORY_ENTRY_IMPORT:
        f.write(f"\t\tDLL: {entry.dll}\n")
        for import_info in entry.imports:
          f.write(f"\t\t\tFunction: {import_info.name}\n")

      # Export information (if available)
      if pe.DIRECTORY_ENTRY_EXPORT:
        f.write("\n\tExported Functions:\n")
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
          f.write(f"\t\t{entry.name}\n")

      # Note about open source libraries
      f.write("\n\tOpen source libraries used cannot be reliably identified from PE files.\n")

  except FileNotFoundError:
    print(f"Error: File '{file_name}' not found.")
  except pefile.PEFormatError:
    print(f"Error: Invalid PE format in file '{file_name}'.")

if __name__ == "__main__":
  analyze_pe_file("testexe.exe")
