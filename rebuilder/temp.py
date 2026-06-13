import argparse
import json
import struct
import sys
import os
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.enums import ENUM_E_TYPE

class OriginalELF:
    def __init__(self, path):
        self.path = path
        self.fd = open(path, 'rb')
        self.elf = ELFFile(self.fd)

        self.e_type = self.elf['e_type'] #dynamic/static
        self.e_machine = self.elf['e_machine'] #arch 64/32
        self.e_entry = self.elf['e_entry'] #OEP

        #self.arch = self._arch_name() #arch name, i.e arm, mips, ..
        self.base_addr = self.find_base_addr() #base addr

        self.pages = {}
        self.prots = {}
        self.parse_sections()
        
    def find_base_addr(self):
        base = 0xFFFFFFFF
        for seg in self.elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                base = min(base, seg['p_vaddr'])
        return base if base != 0xFFFFFFFF else 0x400000
    def parse_sections(self):
        for section in self.elf.iter_sections():
            name = section.name
            vaddr = section['sh_addr']
            size = section['sh_size']
            sec_type = section['sh_type']  # SHT_PROGBITS, SHT_NOBITS, etc.

            if size == 0 or vaddr == 0:
                continue

            prot = 0x1  # R
            if section['sh_flags'] & 0x1:
                prot |= 0x2  # W
            if section['sh_flags'] & 0x4:
                prot |= 0x4  # X

            if sec_type == 'SHT_NOBITS':
                #nobits, main .bss, other as well exists
                #TODO
                self._record_bss(vaddr, size, prot)
                continue

            data = section.data()
            if not data:
                continue

            # split into pages
            for offset in range(0, len(data), 0x1000):
                page_addr = vaddr + offset
                page_data = data[offset:offset + 0x1000]

                if len(page_data) < 0x1000:
                    page_data = page_data + b'\x00' * (0x1000 - len(page_data))

                self.pages[page_addr] = page_data
                self.prots[page_addr] = prot

        print(f"[ORIG] Parsed {len(self.pages)} pages from sections")
