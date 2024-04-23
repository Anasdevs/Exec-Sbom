import pefile
import peutils
import os

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)

        # Open output file for writing
        with open("output.txt", "w") as output_file:

            # Write header analysis to output file
            output_file.write("Header Analysis:\n")
            output_file.write("Signature: {}\n".format(hex(pe.DOS_HEADER.e_magic)))
            output_file.write("Machine: {}\n".format(pe.FILE_HEADER.Machine))
            output_file.write("Number of Sections: {}\n".format(pe.FILE_HEADER.NumberOfSections))
            output_file.write("Time Date Stamp: {}\n".format(pe.FILE_HEADER.TimeDateStamp))
            output_file.write("Entry Point: 0x{:x}\n".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            output_file.write("Image Base: 0x{:x}\n".format(pe.OPTIONAL_HEADER.ImageBase))

            # Write section headers to output file
            output_file.write("\nSection Headers:\n")
            for section in pe.sections:
                output_file.write("Name: {}\n".format(section.Name.decode().rstrip('\x00')))
                output_file.write("\tVirtual Address: 0x{:x}\n".format(section.VirtualAddress))
                output_file.write("\tVirtual Size: {}\n".format(section.Misc_VirtualSize))
                output_file.write("\tRaw Size: {}\n".format(section.SizeOfRawData))
                output_file.write("\tEntropy: {:.2f}\n".format(section.get_entropy()))

            # Analyze dependencies and write to output file
            analyze_dependencies(pe, output_file)

            # List kernel32 functions and write to output file
            list_kernel32_functions(pe, output_file)


    except Exception as e:
        print("Error:", e)

def analyze_dependencies(pe, output_file):
    try:
        # Dictionary to store imported DLLs and their imported functions
        dependencies = {}

        # Analyze the import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            dependencies[dll_name] = []

            for imp in entry.imports:
                if imp.name:
                    function_name = imp.name.decode('utf-8')
                else:
                    function_name = "Ordinal {}".format(imp.ordinal)

                dependencies[dll_name].append(function_name)

        # Write dependencies to output file
        output_file.write("\nDependency Analysis:\n")
        output_file.write("Imported DLLs and Functions:\n")
        for dll, functions in dependencies.items():
            output_file.write("{}\n".format(dll))
            for function in functions:
                output_file.write("\t{}\n".format(function))

    except AttributeError:
        output_file.write("\nNo Delay-Loaded DLLs found.")

def list_kernel32_functions(pe, output_file):
    try:
        # Set to store imported functions from kernel32.dll (to avoid duplicates)
        kernel32_functions = set()

        # Analyze the import table for kernel32.dll
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode('utf-8').lower() == 'kernel32.dll':
                for imp in entry.imports:
                    if imp.name:
                        function_name = imp.name.decode('utf-8')
                        # kernel32_functions.add(function_name)

        # Write kernel32 functions to output file
        # output_file.write("\nImported Functions from kernel32.dll:\n")
        for function in kernel32_functions:
            output_file.write("{}\n".format(function))

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    pe_file_path = "ChromeSetup.exe"
    analyze_pe_file(pe_file_path)
