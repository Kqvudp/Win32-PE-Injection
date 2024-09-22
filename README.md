# Win32-PE-Injection

Python code to automatically insert shellcode into a 32-bit executable file to display a basic message box using the following formulas:

Offset = RA – Section RA = VA – Section VA
new_entry_point (Section VA) = Section RA – RA + VA
Old_entry_point = AddressOfEntryPoint + ImageBase
Old_entry_point = jmp_instruction_VA (new_entry_point + 14) + 5 + relative_VA
