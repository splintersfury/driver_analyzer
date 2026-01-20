#!/usr/bin/env python3
"""
Create a minimal Windows driver PE file for testing.
This creates a valid PE structure with Native subsystem (driver indicator).
"""
import struct

def create_driver_pe():
    # DOS Header
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    # e_lfanew - pointer to PE header (at offset 64)
    struct.pack_into('<I', dos_header, 60, 64)
    
    # PE Signature
    pe_sig = b'PE\x00\x00'
    
    # COFF File Header (20 bytes)
    coff_header = bytearray(20)
    struct.pack_into('<H', coff_header, 0, 0x8664)  # Machine: AMD64
    struct.pack_into('<H', coff_header, 2, 1)       # NumberOfSections
    struct.pack_into('<I', coff_header, 4, 0)       # TimeDateStamp
    struct.pack_into('<I', coff_header, 8, 0)       # PointerToSymbolTable
    struct.pack_into('<I', coff_header, 12, 0)      # NumberOfSymbols
    struct.pack_into('<H', coff_header, 16, 240)    # SizeOfOptionalHeader (PE32+)
    struct.pack_into('<H', coff_header, 18, 0x22)   # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)
    
    # Optional Header (PE32+) - 240 bytes
    opt_header = bytearray(240)
    struct.pack_into('<H', opt_header, 0, 0x20b)    # Magic: PE32+
    struct.pack_into('<B', opt_header, 2, 14)       # MajorLinkerVersion
    struct.pack_into('<B', opt_header, 3, 0)        # MinorLinkerVersion
    struct.pack_into('<I', opt_header, 4, 0x200)    # SizeOfCode
    struct.pack_into('<I', opt_header, 8, 0)        # SizeOfInitializedData
    struct.pack_into('<I', opt_header, 12, 0)       # SizeOfUninitializedData
    struct.pack_into('<I', opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into('<I', opt_header, 20, 0x1000)  # BaseOfCode
    struct.pack_into('<Q', opt_header, 24, 0x10000) # ImageBase
    struct.pack_into('<I', opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into('<I', opt_header, 36, 0x200)   # FileAlignment
    struct.pack_into('<H', opt_header, 40, 6)       # MajorOperatingSystemVersion
    struct.pack_into('<H', opt_header, 42, 0)       # MinorOperatingSystemVersion
    struct.pack_into('<H', opt_header, 44, 0)       # MajorImageVersion
    struct.pack_into('<H', opt_header, 46, 0)       # MinorImageVersion
    struct.pack_into('<H', opt_header, 48, 6)       # MajorSubsystemVersion
    struct.pack_into('<H', opt_header, 50, 0)       # MinorSubsystemVersion
    struct.pack_into('<I', opt_header, 52, 0)       # Win32VersionValue
    struct.pack_into('<I', opt_header, 56, 0x3000)  # SizeOfImage
    struct.pack_into('<I', opt_header, 60, 0x200)   # SizeOfHeaders
    struct.pack_into('<I', opt_header, 64, 0)       # CheckSum
    struct.pack_into('<H', opt_header, 68, 1)       # Subsystem: NATIVE (1) - DRIVER!
    struct.pack_into('<H', opt_header, 70, 0)       # DllCharacteristics
    struct.pack_into('<Q', opt_header, 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into('<Q', opt_header, 80, 0x1000)    # SizeOfStackCommit
    struct.pack_into('<Q', opt_header, 88, 0x100000)  # SizeOfHeapReserve
    struct.pack_into('<Q', opt_header, 96, 0x1000)    # SizeOfHeapCommit
    struct.pack_into('<I', opt_header, 104, 0)        # LoaderFlags
    struct.pack_into('<I', opt_header, 108, 16)       # NumberOfRvaAndSizes
    # Data directories (16 entries, each 8 bytes) - all zeros for minimal PE
    
    # Section Header (40 bytes)
    section_header = bytearray(40)
    section_header[0:8] = b'.text\x00\x00\x00'  # Name
    struct.pack_into('<I', section_header, 8, 0x100)   # VirtualSize
    struct.pack_into('<I', section_header, 12, 0x1000) # VirtualAddress
    struct.pack_into('<I', section_header, 16, 0x200)  # SizeOfRawData
    struct.pack_into('<I', section_header, 20, 0x200)  # PointerToRawData
    struct.pack_into('<I', section_header, 24, 0)      # PointerToRelocations
    struct.pack_into('<I', section_header, 28, 0)      # PointerToLinenumbers
    struct.pack_into('<H', section_header, 32, 0)      # NumberOfRelocations
    struct.pack_into('<H', section_header, 34, 0)      # NumberOfLinenumbers
    struct.pack_into('<I', section_header, 36, 0x60000020)  # Characteristics: CODE, EXECUTE, READ
    
    # Padding to reach section data at 0x200
    headers = dos_header + pe_sig + coff_header + opt_header + section_header
    padding = b'\x00' * (0x200 - len(headers))
    
    # Minimal code section (ret instruction)
    code = b'\xc3' + b'\x00' * 0x1FF  # 0x200 bytes
    
    return headers + padding + code

if __name__ == "__main__":
    pe_data = create_driver_pe()
    with open("/tmp/test_native_driver.sys", "wb") as f:
        f.write(pe_data)
    print(f"Created test driver: /tmp/test_native_driver.sys ({len(pe_data)} bytes)")
