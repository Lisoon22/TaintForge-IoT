import argparse
import json
import struct
import sys
import os
from elftools.elf.elffile import ELFFile

def page_get(pages, addr):
    return pages.get(addr & ~0xFFF, None)

def page_has(pages, addr):
    return (addr & ~0xFFF) in pages

def prot_get(prots, addr):
    return prots.get(addr & ~0xFFF, 0x5)

def pad_to_page(data):
    if len(data) < 0x1000:
        return data + b'\x00' * (0x1000 - len(data))
    return data

def split_to_pages(data, base_addr, prot):
    pages, prots = {}, {}
    aligned_base = base_addr & ~0xFFF
    prefix = base_addr - aligned_base
    if prefix:
        data = b'\x00' * prefix + data
    for offset in range(0, len(data), 0x1000):
        page_addr = aligned_base + offset
        pages[page_addr] = pad_to_page(data[offset:offset + 0x1000])
        prots[page_addr] = prot
    return pages, prots

def parse_original_elf(path):
    result = {
        'pages': {}, 'prots': {}, 'nobits': {}, 'base_addr': 0,
        'e_type': 0, 'e_machine': 0, 'e_entry': 0,
        'arch': '', 'interp': None, 'dynamic': None, 'osabi': 0,
    }

    with open(path, 'rb') as f:
        elf = ELFFile(f)
        e_type_val = elf.header['e_type']
        if isinstance(e_type_val, str):
            e_type_map = {'ET_EXEC': 2, 'ET_DYN': 3, 'ET_REL': 1, 'ET_CORE': 4}
            result['e_type'] = e_type_map.get(e_type_val, 2)
        else:
            result['e_type'] = int(e_type_val)
        result['e_machine'] = elf['e_machine']
        result['e_entry'] = elf['e_entry']
        osabi_map = {
            'ELFOSABI_SYSV': 0, 'ELFOSABI_HPUX': 1, 'ELFOSABI_NETBSD': 2,
            'ELFOSABI_GNU': 3, 'ELFOSABI_SOLARIS': 6, 'ELFOSABI_AIX': 7,
            'ELFOSABI_IRIX': 8, 'ELFOSABI_FREEBSD': 9, 'ELFOSABI_TRU64': 10,
            'ELFOSABI_MODESTO': 11, 'ELFOSABI_OPENBSD': 12,
            'ELFOSABI_ARM_AEABI': 64, 'ELFOSABI_ARM': 97, 'ELFOSABI_STANDALONE': 255,
            }
        result['osabi'] = osabi_map.get(elf.header['e_ident']['EI_OSABI'], 0)

        m = {
                3: 'i386', 'EM_386': 'i386', '386': 'i386',
                62: 'x86-64', 'EM_X86_64': 'x86-64',
                40: 'arm', 'EM_ARM': 'arm',
                183: 'aarch64', 'EM_AARCH64': 'aarch64',
            }
        result['arch'] = m.get(elf['e_machine'], f'unknown({elf["e_machine"]})')

        base = 0xFFFFFFFF
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            vaddr = seg['p_vaddr']
            filesz = seg['p_filesz']
            if filesz == 0:
                continue
            seg_prot = 0x0
            if seg['p_flags'] & 0x4: seg_prot |= 0x1  # PF_R
            if seg['p_flags'] & 0x2: seg_prot |= 0x2  # PF_W
            if seg['p_flags'] & 0x1: seg_prot |= 0x4  # PF_X
    
            seg_data = seg.data()
            memsz = seg['p_memsz']
            filesz = seg['p_filesz']
            if seg_data and memsz > filesz:
                seg_data += b'\x00' * (memsz - filesz)
            if seg_data:
                p, pr = split_to_pages(seg_data, vaddr, seg_prot)
                result['pages'].update(p)
                result['prots'].update(pr)

        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                base = min(base, seg['p_vaddr'])
        result['base_addr'] = base if base != 0xFFFFFFFF else 0x400000

        for section in elf.iter_sections():
            vaddr = section['sh_addr']
            size = section['sh_size']
            if size == 0 or vaddr == 0:
                continue

            prot = 0x1
            if section['sh_flags'] & 0x1: prot |= 0x2
            if section['sh_flags'] & 0x4: prot |= 0x4

            if section['sh_type'] == 'SHT_NOBITS':
                for offset in range(0, size, 0x1000):
                    page_addr = vaddr + offset
                    result['nobits'][page_addr] = prot
                continue

            data = section.data()
            if not data:
                continue
            p, pr = split_to_pages(data, vaddr, prot)
            for page_addr in p:
                aligned_addr = page_addr & ~0xFFF
                if aligned_addr in result['pages']:
                    result['prots'][aligned_addr] = prot

        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_INTERP':
                result['interp'] = seg.get_interp_name()
            elif seg['p_type'] == 'PT_DYNAMIC':
                result['dynamic'] = seg.data()

    print(f"[ORIG] {path}: {result['arch']}, {len(result['pages'])} pages, base=0x{result['base_addr']:x}")
    return result


def parse_dump(bin_path, json_path):
    result = {
        'pages': {}, 'prots': {}, 'written': {},
        'oep': 0, 'regions': [], 'library_dependencies': [],
    }

    with open(json_path) as f:
        meta = json.load(f)

    result['oep'] = int(meta['oep'], 16)
    result['regions'] = meta['regions']
    result['library_dependencies'] = meta.get('library_dependencies', [])

    with open(bin_path, 'rb') as f:
        raw = f.read()

    for r in meta['regions']:
        addr = int(r['addr'], 16)
        size = r['size']
        prot = r['prot']
        region_data = raw[r['offset']:r['offset'] + size]

        p, pr = split_to_pages(region_data, addr, prot)
        result['pages'].update(p)
        result['prots'].update(pr)
        for a in p:
            result['written'][a] = (prot & 0x2) != 0

    print(f"[DUMP] {bin_path}: {len(result['pages'])} pages, OEP=0x{result['oep']:x}")
    return result

def is_library(addr, dump):
    for lib in dump.get('library_dependencies', []):
        base = int(lib.get('base', '0x0'), 16)
        size = lib.get('size', 0)
        if base == 0 or size == 0:
            continue
        if base <= addr < base + size:
            return True
    return False

def classify_pages(orig, dump):
    result = []
    
    # all unique page addresses from both sources
    all_addrs = sorted(set(
        list(orig['pages'].keys()) + 
        list(dump['pages'].keys())
    ))
    
    for addr in all_addrs:
        orig_page = page_get(orig['pages'], addr)
        dump_page = page_get(dump['pages'], addr)
        
        if orig_page is not None and dump_page is not None:
            if orig_page == dump_page:
                # if unchanged we take original
                result.append({
                    'addr': addr, 'source': 'original',
                    'data': orig_page, 'prot': prot_get(orig['prots'], addr)
                })
            else:
                # modified: we take dump
                result.append({
                    'addr': addr, 'source': 'dump',
                    'data': dump_page, 'prot': prot_get(dump['prots'], addr)
                })
        
        elif orig_page is not None and dump_page is None:
            # only original - unmodified section maybe some important data
            result.append({
                'addr': addr, 'source': 'original',
                'data': orig_page, 'prot': prot_get(orig['prots'], addr)
            })
        
        elif dump_page is not None and orig_page is None:
            # only dump - new memory from packer or library
            if is_library(addr, dump):
                continue  # skip libc, ld-linux
            
            result.append({
                'addr': addr, 'source': 'dump',
                'data': dump_page, 'prot': prot_get(dump['prots'], addr)
            })
    
    # NOBITS (.bss, .tbss): zero-fill pages not modified by packer
    existing_addrs = {pg['addr'] for pg in result}
    for addr, prot in orig.get('nobits', {}).items():
        aligned_addr = addr & ~0xFFF
        if aligned_addr in existing_addrs:
            continue
        if not page_has(dump['pages'], aligned_addr):
            result.append({
                'addr': aligned_addr, 'source': 'zero',
                'data': b'\x00' * 0x1000, 'prot': prot
            })
            existing_addrs.add(aligned_addr)
    result.sort(key=lambda x: x['addr'])
    return result

class ELFBuilder:
    def __init__(self, classified_pages, oep, arch='i386', e_type=2, interp=None, osabi=0):
        self.pages = sorted(classified_pages, key=lambda x: x['addr'])
        self.oep = oep
        self.arch = arch
        self.e_type = e_type
        self.interp = interp
        self.osabi = osabi

    def build(self, output_path):
        #continuous pages into groups
        segments = self.collect_pages()
        
        interp_data = None
        interp_padded = None
        if self.interp:
            interp_data = self.interp.encode('utf-8') + b'\x00'
            interp_padded = interp_data + b'\x00' * ((0x1000 - len(interp_data) % 0x1000) % 0x1000)
        
        header_size = 52 + 32 * (1 + (1 if self.interp else 0) + len(segments))
        data_offset = (header_size + 0xFFF) & ~0xFFF
        phdrs_data, num_phdrs = self.build_phdrs(segments, interp_data, interp_padded, data_offset)
        ehdr = self.build_ehdr(num_phdrs)
        pad_size = data_offset - (52 + 32 * num_phdrs)

        with open(output_path, 'wb') as f:
            f.write(ehdr)
            f.write(phdrs_data)
            f.write(b'\x00' * pad_size)
            
            if interp_padded:
                f.write(interp_padded)
            
            for seg in segments:
                padded = seg['data'] + b'\x00' * ((0x1000 - len(seg['data']) % 0x1000) % 0x1000)
                f.write(padded)
        
        print(f"[BUILD] {output_path}: {num_phdrs} phdrs, {len(segments)} segments, OEP=0x{self.oep:x}")
        return True

    def collect_pages(self):
        if not self.pages:
            return []
        segments = []
        cur = {
            'addr': self.pages[0]['addr'],
            'data': self.pages[0]['data'],
            'prot': self.pages[0]['prot']
        }
        for page in self.pages[1:]:
            prev_end = cur['addr'] + len(cur['data'])
            if page['addr'] == prev_end and page['prot'] == cur['prot']:
                # merge contiguous and with same prot
                cur['data'] += page['data']
            else:
                segments.append(cur)
                cur = {
                    'addr': page['addr'],
                    'data': page['data'],
                    'prot': page['prot']
                }
        segments.append(cur)
        return segments

    def build_ehdr(self, num_phdrs):
        """Build ELF32_Ehdr (52 bytes)."""
        if self.arch == 'i386':
            e_machine = 3
            e_entry = self.oep & 0xFFFFFFFF
        elif self.arch == 'x86-64':
            e_machine = 62
            # TODO 64 bytes
            raise NotImplementedError("x86-64 ELF64 not yet implemented")
        else:
            raise ValueError(f"Unknown arch: {self.arch}")

        ehdr = struct.pack('<4sBBBBB7xHHIIIIIHHHHHH',
            #e_ident
            b'\x7fELF', # elf magic
            1, # 32 bits
            1, # LSB
            1, # 1 for version
            self.osabi, # OS/ABI
            0, # SYSSV
            self.e_type,     # e_type: ET_EXEC or ET_DYN
            e_machine,       # e_machine
            1,               # e_version
            e_entry,         # e_entry OEP
            52,              # e_phoff sizeof(Ehdr)
            0,               # e_shoff (no sections)
            0,               # e_flags
            52,              # e_ehsize
            32,              # e_phentsize sizeof(Phdr)
            num_phdrs,       # e_phnum
            40,              # e_shentsize
            0,               # e_shnum
            0)               # e_shstrndx

        return ehdr

    def build_phdrs(self, segments, interp_data=None, interp_padded=None, start_offset=None):
        phdrs = b''
        if start_offset is None:
            phdrs_est = 1 + (1 if self.interp else 0) + len(segments)
            start_offset = 52 + 32 * phdrs_est
        offset = start_offset # headers then data
        num_phdrs = 0

        phdr = struct.pack('<IIIIIIII', 0x6474e551, 0, 0, 0, 0, 0, 0x6, 0x1000)
        phdrs += phdr
        num_phdrs += 1

        if self.interp:
            phdr = struct.pack('<IIIIIIII', 3, offset, 0, 0, len(interp_data), len(interp_data), 0x4, 1)
            phdrs += phdr
            num_phdrs += 1
            offset += len(interp_padded)


        for seg in segments:
            flags = 0
            if seg['prot'] & 0x1: flags |= 4  # PF_R
            if seg['prot'] & 0x2: flags |= 2  # PF_W
            if seg['prot'] & 0x4: flags |= 1  # PF_X

            filesz = len(seg['data'])
            filesz_padded = filesz + (0x1000 - filesz % 0x1000) % 0x1000

            phdr = struct.pack('<IIIIIIII',
                1,              # p_type = PT_LOAD
                offset,         # p_offset  <-- теперь кратен 0x1000
                seg['addr'],    # p_vaddr
                seg['addr'],    # p_paddr
                filesz_padded,  # p_filesz
                filesz_padded,  # p_memsz
                flags,          # p_flags
                0x1000)         # p_align

            phdrs += phdr
            num_phdrs += 1
            offset += filesz_padded

        return phdrs, num_phdrs
def parse_args():
    parser = argparse.ArgumentParser(
        description="Rebuild ELF from unpacker dump with original reference"
    )
    parser.add_argument(
        "-b", "--bin", required=True,
        help="Path to unpacked binary (raw memory dump)"
    )
    parser.add_argument(
        "-j", "--json", required=True,
        help="Path to unpacked json"
    )
    parser.add_argument(
        "-e", "--elf", required=True,
        help="Path to original packed ELF"
    )
    parser.add_argument(
        "-o", "--output", default="rebuilt.elf",
        help="Output path for rebuilt ELF (default: rebuilt.elf)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print detailed merge log"
    )

    args = parser.parse_args()

    # Validate inputs exist
    for path_attr, label in [("bin", "Dump binary"), ("json", "JSON metadata"), ("elf", "Original ELF")]:
        if not os.path.exists(getattr(args, path_attr)):
            print(f"[-] Error: {label} not found: {getattr(args, path_attr)}", file=sys.stderr)
            sys.exit(1)

    return args

def resolve_entry_point(orig, dump):
    """Выбираем entry point в зависимости от сценария."""
    
    # PIE-bin
    if orig['e_type'] == 3:  # ET_DYN
        return dump['oep']
    
    # Static ELF
    if orig['e_type'] == 2:  # ET_EXEC
        return orig.get('e_entry', dump['oep'])
    
    # Default
    return dump['oep']

def main():
    args = parse_args()
    print(f"[+] Dump binary : {args.bin}")
    print(f"[+] JSON metadata: {args.json}")
    print(f"[+] Original ELF : {args.elf}")
    print(f"[+] Output       : {args.output}")
    # Phase 1: Parse
    orig = parse_original_elf(args.elf)
    dump = parse_dump(args.bin, args.json)

    # Phase 2: Merge
    print("[+] Classifying pages...")
    classified = classify_pages(orig, dump)
    print(f"[+] {len(classified)} pages classified")

    # Phase 3: Build
    entry_point = resolve_entry_point(orig, dump)#orig.get('e_entry', dump['oep'])#dump['oep']
    builder = ELFBuilder(classified, entry_point, arch=orig['arch'], e_type=2, interp=orig.get('interp'), osabi=orig.get('osabi', 0))
    builder.build(args.output)

    print(f"[+] Done: {args.output}")
if __name__ == "__main__":
    main()
