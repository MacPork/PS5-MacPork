#!/usr/bin/env python3
"""
PS5 MacPork
A native macOS GUI for backporting PS5 game dumps to lower firmware versions.

Credits:
  - idlesauce       : ps5_elf_sdk_downgrade.py (SDK version patching logic)
  - BestPig         : BackPork (fakelib sideloading concept & BPS patches)
  - john-tornblom   : make_fself.py (ELF → fake-signed SELF re-signing)
  - CyB1K/dmiller423 : SelfUtil (FSELF → ELF conversion)
  - BackPork Kitchen : workflow inspiration

Requires Python 3.8+ — no external dependencies.
Usage: python3 ps5_backport_mac.py
"""

import os, struct, shutil, zlib, hashlib, io, json, webbrowser, tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from datetime import datetime
import threading


# ── Persistent config ──────────────────────────────────────────────────────
CONFIG_PATH = os.path.expanduser("~/.ps5_backport_tool.json")

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_config(data):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(data, f, indent=2)
    except:
        pass

# ── SDK version pairs (fw_label → (ps5_sdk_ver, ps4_ver)) ─────────────────
SDK_VERSION_PAIRS = {
    "FW 4.xx": (0x04000031, 0x09040001),
    "FW 5.xx": (0x05000033, 0x09590001),
    "FW 6.xx": (0x06000038, 0x10090001),
    "FW 7.xx": (0x07000038, 0x10590001),
}

PATCHABLE_EXT  = {".bin", ".elf", ".self", ".prx", ".sprx"}
ELF_MAGIC      = b'\x7FELF'
PS4_FSELF      = b'\x4F\x15\x3D\x1D'
PS5_FSELF      = b'\x54\x14\xF5\xEE'

# ELF struct constants
PT_SCE_PROCPARAM    = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002
SCE_PROC_MAGIC      = 0x4942524F
SCE_MOD_MAGIC       = 0x3C13F4BF
FMT                 = {1:'<B',2:'<H',4:'<I',8:'<Q'}

def rdi(f, off, sz):
    f.seek(off); return struct.unpack(FMT[sz], f.read(sz))[0]

def wri(f, off, sz, v):
    f.seek(off); f.write(struct.pack(FMT[sz], v))


# ── BPS patcher ────────────────────────────────────────────────────────────

def _varint(data, pos):
    result, shift = 0, 1
    while True:
        b = data[pos]; pos += 1
        result += (b & 0x7F) * shift
        if b & 0x80: break
        shift <<= 7; result += shift
    return result, pos

def apply_bps(patch_bytes, source_bytes):
    if patch_bytes[:4] != b'BPS1':
        raise ValueError("Not a valid BPS patch (bad magic)")

    patch_crc = struct.unpack('<I', patch_bytes[-4:])[0]
    if (zlib.crc32(patch_bytes[:-4]) & 0xFFFFFFFF) != patch_crc:
        raise ValueError("Patch CRC mismatch — corrupt patch file")

    pos = 4
    source_size, pos = _varint(patch_bytes, pos)
    target_size, pos = _varint(patch_bytes, pos)
    meta_size,   pos = _varint(patch_bytes, pos)
    pos += meta_size

    target         = bytearray(target_size)
    out_off        = 0
    src_rel        = 0
    tgt_rel        = 0
    patch_end      = len(patch_bytes) - 12

    while pos < patch_end:
        ad, pos = _varint(patch_bytes, pos)
        action  = ad & 3
        length  = (ad >> 2) + 1

        if action == 0:   # SourceRead
            target[out_off:out_off+length] = source_bytes[out_off:out_off+length]
            out_off += length
        elif action == 1: # TargetRead
            target[out_off:out_off+length] = patch_bytes[pos:pos+length]
            pos += length; out_off += length
        elif action == 2: # SourceCopy
            raw, pos = _varint(patch_bytes, pos)
            src_rel += (raw >> 1) * (-1 if raw & 1 else 1)
            target[out_off:out_off+length] = source_bytes[src_rel:src_rel+length]
            src_rel += length; out_off += length
        elif action == 3: # TargetCopy
            raw, pos = _varint(patch_bytes, pos)
            tgt_rel += (raw >> 1) * (-1 if raw & 1 else 1)
            for i in range(length):
                target[out_off+i] = target[tgt_rel+i]
            tgt_rel += length; out_off += length

    src_crc = struct.unpack('<I', patch_bytes[-12:-8])[0]
    if (zlib.crc32(source_bytes[:source_size]) & 0xFFFFFFFF) != src_crc:
        raise ValueError("Source CRC mismatch — wrong source file for this patch")

    return bytes(target)


# ── ELF SDK downgrade ──────────────────────────────────────────────────────

def _patch_elf_segments(f, ps5_ver, ps4_ver, log):
    seg_count  = rdi(f, 0x38, 2)
    pht_offset = rdi(f, 0x20, 8)
    patched    = False

    for i in range(seg_count):
        base     = pht_offset + i * 0x38
        seg_type = rdi(f, base, 4)
        if seg_type not in (PT_SCE_PROCPARAM, PT_SCE_MODULE_PARAM):
            continue

        seg_off    = rdi(f, base + 0x8, 8)
        param_size = rdi(f, seg_off, 4)

        if param_size == 0 and seg_type == PT_SCE_MODULE_PARAM:
            log("    [?] No param struct in module — skip"); return True

        if param_size < 0x18:
            log(f"    [!] Unexpected param size 0x{param_size:X}"); return False

        magic    = rdi(f, seg_off + 0x8, 4)
        expected = SCE_PROC_MAGIC if seg_type == PT_SCE_PROCPARAM else SCE_MOD_MAGIC
        if magic != expected:
            log(f"    [!] Bad magic 0x{magic:08X}"); return False

        orig = rdi(f, seg_off + 0x14, 4)
        wri(f, seg_off + 0x14, 4, ps5_ver)
        wri(f, seg_off + 0x10, 4, ps4_ver)
        log(f"    [✓] SDK 0x{orig:08X} → 0x{ps5_ver:08X}")
        patched = True

    return patched


def sdk_downgrade_file(src_path, backup_dir, game_dir, ps5_ver, ps4_ver, log):
    with open(src_path, 'rb') as f:
        magic = f.read(4)

    if magic in (PS4_FSELF, PS5_FSELF):
        log(f"    [!] Signed SELF — needs decryption first, skipped")
        return "skipped_signed"
    if magic != ELF_MAGIC:
        return "skipped_not_elf"

    rel         = os.path.relpath(src_path, game_dir)
    backup_path = os.path.join(backup_dir, rel)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    if not os.path.exists(backup_path):
        shutil.copy2(src_path, backup_path)

    with open(src_path, 'r+b') as f:
        ok = _patch_elf_segments(f, ps5_ver, ps4_ver, log)

    return "patched" if ok else "skipped_no_param"


# ── FSELF → ELF conversion (based on dmiller423/selfutil) ─────────────────
# PS4 FSELF magic: 0x4F153D1D
# PS5 FSELF magic: 0x5414F5EE
# Structure: Self_Hdr (0x20) + num_entries * Self_Entry (0x20) + ELF header + segments

SELF_MAGIC_PS4 = 0x1D3D154F  # bytes [4F 15 3D 1D] read as little-endian uint32
SELF_MAGIC_PS5 = 0xEEF51454  # bytes [54 14 F5 EE] read as little-endian uint32
PS4_PAGE_SIZE  = 0x4000

def fself_to_elf(data):
    """Convert PS4/PS5 FSELF bytes to plain ELF bytes. Returns ELF bytes or None."""
    if len(data) < 0x20:  # Must have at least the Self_Hdr
        return None

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic not in (SELF_MAGIC_PS4, SELF_MAGIC_PS5):
        return None

    # Self_Hdr is 0x20 bytes, followed by num_entries Self_Entry structs (each 0x20 bytes)
    # num_entries is at offset 0x18 in Self_Hdr
    num_entries = struct.unpack_from('<H', data, 0x18)[0]

    # Self_Entry is 0x20 bytes: props(8), offs(8), fileSz(8), memSz(8)
    # Entries start at offset 0x20 (right after the 0x20-byte Self_Hdr)
    entries = []
    for i in range(num_entries):
        base = 0x20 + i * 0x20
        props  = struct.unpack_from('<Q', data, base + 0x00)[0]
        offs   = struct.unpack_from('<Q', data, base + 0x08)[0]
        fileSz = struct.unpack_from('<Q', data, base + 0x10)[0]
        memSz  = struct.unpack_from('<Q', data, base + 0x18)[0]
        entries.append((props, offs, fileSz, memSz))

    # ELF header starts right after Self_Hdr + entries
    elf_hdr_off = 0x20 + num_entries * 0x20

    # If ELF magic not found there, search for it (handles padding variants)
    if data[elf_hdr_off:elf_hdr_off+4] != b'\x7FELF':
        idx = data.find(b'\x7FELF', 0x20)
        if idx == -1:
            return None
        elf_hdr_off = idx

    # Final validation
    if data[elf_hdr_off:elf_hdr_off+4] != b'\x7FELF':
        return None

    # Read ELF program header info: e_phoff(8) at +0x20, e_phnum(2) at +0x38
    e_phoff = struct.unpack_from('<Q', data, elf_hdr_off + 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, elf_hdr_off + 0x38)[0]

    # Read program headers to find save size
    save_size = 0
    phdrs = []
    for i in range(e_phnum):
        ph_base = elf_hdr_off + e_phoff + i * 0x38
        p_type    = struct.unpack_from('<I', data, ph_base + 0x00)[0]
        p_flags   = struct.unpack_from('<I', data, ph_base + 0x04)[0]
        p_offset  = struct.unpack_from('<Q', data, ph_base + 0x08)[0]
        p_vaddr   = struct.unpack_from('<Q', data, ph_base + 0x10)[0]
        p_paddr   = struct.unpack_from('<Q', data, ph_base + 0x18)[0]
        p_filesz  = struct.unpack_from('<Q', data, ph_base + 0x20)[0]
        p_memsz   = struct.unpack_from('<Q', data, ph_base + 0x28)[0]
        p_align   = struct.unpack_from('<Q', data, ph_base + 0x30)[0]
        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_paddr,
                      p_filesz, p_memsz, p_align))
        if p_offset > 0:
            save_size = max(save_size, p_offset + p_filesz)

    # Align up to page size
    save_size = (save_size + PS4_PAGE_SIZE - 1) & ~(PS4_PAGE_SIZE - 1)
    if save_size == 0:
        save_size = len(data)

    out = bytearray(save_size)

    # Find first segment offset to determine how much of the header to copy
    first_off = min((ph[2] for ph in phdrs if ph[2] > 0), default=elf_hdr_off)
    # Copy from ELF header up to first segment
    copy_len = min(first_off, len(data) - elf_hdr_off)
    out[0:copy_len] = data[elf_hdr_off:elf_hdr_off + copy_len]

    # Copy each segment that has the "blocked" flag (0x800) set in props
    for (props, offs, fileSz, memSz) in entries:
        if not (props & 0x800):
            continue
        ph_idx = (props >> 20) & 0xFFF
        if ph_idx >= len(phdrs):
            continue
        p_offset = phdrs[ph_idx][2]
        src = data[offs:offs + fileSz]
        out[p_offset:p_offset + len(src)] = src

    return bytes(out)


def unfself_file(src_path, backup_dir, game_dir, log):
    """Convert a single FSELF file to ELF in-place, backing up the original."""
    with open(src_path, 'rb') as f:
        data = f.read()

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic not in (SELF_MAGIC_PS4, SELF_MAGIC_PS5):
        return "skipped_not_fself"

    elf_data = fself_to_elf(data)
    if elf_data is None:
        # Log more detail for debugging
        num_e = struct.unpack_from('<H', data, 0x18)[0] if len(data) >= 0x1A else 0
        calc_off = 0x20 + num_e * 0x20
        found_off = data.find(b'\x7FELF', 0x20)
        log(f"    [!] FSELF conversion failed (num_entries={num_e} calc_off=0x{calc_off:04X} elf_found=0x{found_off:04X})")
        return "error"

    # Validate output has ELF magic
    if elf_data[:4] != b'\x7FELF':
        log(f"    [!] Output not valid ELF")
        return "error"

    # Back up original
    rel         = os.path.relpath(src_path, game_dir)
    backup_path = os.path.join(backup_dir, rel)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    if not os.path.exists(backup_path):
        shutil.copy2(src_path, backup_path)

    with open(src_path, 'wb') as f:
        f.write(elf_data)

    log(f"    [✓] Converted FSELF → ELF ({len(data)} → {len(elf_data)} bytes)")
    return "converted"


# ── make_fself (ELF → fake-signed SELF) ────────────────────────────────────
# Based on make_fself.py by john-tornblom (ps5-payload-dev/sdk)
# https://github.com/ps5-payload-dev/sdk/blob/master/samples/install_app/make_fself.py

import hashlib, io

def _sha256(data):
    return hashlib.sha256(data).digest()

def _align_up(x, a):
    return (x + a - 1) & ~(a - 1)

def _ilog2(x):
    return len(bin(x)) - 3

# ELF constants
_ELF_MAGIC       = b'\x7FELF'
_ET_SCE_EXEC     = 0xFE00
_ET_SCE_EXEC_ASLR= 0xFE10
_ET_SCE_DYNAMIC  = 0xFE18
_PT_LOAD         = 0x1
_PT_SCE_RELRO    = 0x61000010
_PT_SCE_DYNLIBDATA=0x61000000
_PT_SCE_COMMENT  = 0x6FFFFF00
_PT_SCE_VERSION  = 0x6FFFFF01

# SELF constants
_SELF_MAGIC      = b'\x4F\x15\x3D\x1D'
_BLOCK_SIZE      = 0x4000
_DIGEST_SIZE     = 0x20
_SIGNATURE_SIZE  = 0x100
_EMPTY_DIGEST    = b'\x00' * _DIGEST_SIZE
_EMPTY_SIG       = b'\x00' * _SIGNATURE_SIZE
_PAID            = 0x3100000000000002
_PTYPE_FAKE      = 0x1

_SEGMENT_TYPES = {_PT_LOAD, _PT_SCE_RELRO, _PT_SCE_DYNLIBDATA, _PT_SCE_COMMENT}


def _read_elf(data):
    """Parse ELF and return (ehdr_dict, list_of_(phdr, segment_bytes))."""
    if data[:4] != _ELF_MAGIC:
        raise ValueError("Not an ELF file")

    ehdr_fmt = '<4s5B6xB2HI3QI6H'
    ehdr_size = struct.calcsize(ehdr_fmt)
    (magic, cls, enc, ver, osabi, abiver, nident,
     etype, machine, eversion, entry, phoff, shoff,
     flags, ehsize, phentsize, phnum,
     shentsize, shnum, shstridx) = struct.unpack_from(ehdr_fmt, data)

    if cls != 2 or enc != 1:
        raise ValueError("Not 64-bit little-endian ELF")
    if etype not in (_ET_SCE_EXEC, _ET_SCE_EXEC_ASLR, _ET_SCE_DYNAMIC, 0x2):
        raise ValueError(f"Unsupported ELF type 0x{etype:04X}")

    ehdr = dict(magic=magic, cls=cls, enc=enc, ver=ver, osabi=osabi,
                abiver=abiver, nident=nident, etype=etype, machine=machine,
                eversion=eversion, entry=entry, phoff=phoff, shoff=shoff,
                flags=flags, ehsize=ehsize, phentsize=phentsize, phnum=phnum,
                shentsize=shentsize, shnum=shnum, shstridx=shstridx)

    phdr_fmt = '<2I6Q'
    phdrs_segs = []
    version_data = None
    for i in range(phnum):
        off = phoff + i * phentsize
        (ptype, pflags, poffset, pvaddr, ppaddr,
         pfilesz, pmemsz, palign) = struct.unpack_from(phdr_fmt, data, off)
        if pfilesz > 0:
            seg = data[poffset:poffset + pfilesz]
        else:
            seg = b''
        phdr = dict(type=ptype, flags=pflags, offset=poffset, vaddr=pvaddr,
                    paddr=ppaddr, filesz=pfilesz, memsz=pmemsz, align=palign)
        if ptype == _PT_SCE_VERSION:
            version_data = seg
        phdrs_segs.append((phdr, seg))

    return ehdr, phdrs_segs, version_data, _sha256(data)


def elf_to_fself(elf_data):
    """Convert plain ELF bytes to fake-signed SELF bytes."""
    ehdr, phdrs_segs, version_data, elf_digest = _read_elf(elf_data)

    # Build entries for segments we care about
    entries = []
    for i, (phdr, seg) in enumerate(phdrs_segs):
        if phdr['type'] not in _SEGMENT_TYPES:
            continue
        # meta entry
        num_blocks = _align_up(phdr['filesz'], _BLOCK_SIZE) // _BLOCK_SIZE if phdr['filesz'] > 0 else 1
        meta_props = (1 << 2) | (1 << 16)  # signed=1, has_digests=1
        meta_props |= (len(entries) + 1) << 20  # segment_index = next entry
        meta_entry = dict(props=meta_props, data=_EMPTY_DIGEST * num_blocks)

        # data entry
        block_size_bits = _ilog2(_BLOCK_SIZE) - 12
        data_props = (1 << 2) | (1 << 11)  # signed=1, has_blocks=1
        data_props |= (block_size_bits & 0xF) << 12
        data_props |= i << 20  # segment_index = phdr index
        data_entry = dict(props=data_props, data=seg)

        entries.append(meta_entry)
        entries.append(data_entry)

    num_entries = len(entries)

    # Calculate header size
    COMMON_HDR_SIZE = struct.calcsize('<4s4B')         # 8
    EXT_HDR_SIZE    = struct.calcsize('<I2HQ2H4x')     # 24
    ENTRY_SIZE      = struct.calcsize('<4Q')            # 32
    EX_INFO_SIZE    = struct.calcsize('<4Q32s')         # 64
    NPDRM_CB_SIZE   = struct.calcsize('<H14x19s13s')    # 48

    elf_hdr_size = max(ehdr['ehsize'],
                       ehdr['phoff'] + ehdr['phentsize'] * ehdr['phnum'])
    elf_hdr_size = _align_up(elf_hdr_size, 16)

    header_size = (COMMON_HDR_SIZE + EXT_HDR_SIZE
                   + num_entries * ENTRY_SIZE
                   + elf_hdr_size)
    header_size = _align_up(header_size, 16)
    header_size += EX_INFO_SIZE + NPDRM_CB_SIZE

    # meta blocks + footer + signature
    META_BLOCK_SIZE  = 80
    META_FOOTER_SIZE = struct.calcsize('<48xI28x')  # 80
    meta_size = num_entries * META_BLOCK_SIZE + META_FOOTER_SIZE + _SIGNATURE_SIZE

    # Assign offsets to entries
    offset = header_size + meta_size
    for entry in entries:
        entry['offset'] = offset
        entry['filesz'] = len(entry['data'])
        entry['memsz']  = entry['filesz']
        offset += entry['filesz']
        offset = _align_up(offset, 16)

    file_size = offset
    flags = 0x2 | (2 << 4)  # signed_block_count=2

    # ── Write output ────────────────────────────────────────────────────────
    out = bytearray(file_size)
    pos = 0

    def wb(data):
        nonlocal pos
        out[pos:pos+len(data)] = data
        pos += len(data)

    def wpack(fmt, *args):
        wb(struct.pack(fmt, *args))

    # Common header
    wpack('<4s4B', _SELF_MAGIC, 0x00, 0x01, 0x01, 0x12)
    # Extended header: key_type, header_size, meta_size, file_size, num_entries, flags
    wpack('<I2HQ2H4x', 0x101, header_size, meta_size, file_size, num_entries, flags)
    # Entries
    for entry in entries:
        wpack('<4Q', entry['props'], entry['offset'], entry['filesz'], entry['memsz'])
    # ELF headers (copy from original)
    elf_hdr_start = pos
    out[pos:pos+elf_hdr_size] = elf_data[:elf_hdr_size]
    pos = elf_hdr_start + elf_hdr_size
    # Pad to alignment
    pos = _align_up(pos, 16)
    # Extended info: paid, ptype, app_version, fw_version, digest
    wpack('<4Q32s', _PAID, _PTYPE_FAKE, 0, 0, elf_digest)
    # NPDRM control block
    wpack('<H14x19s13s', 0x3, b'\x00' * 19, b'\x00' * 13)
    # Meta blocks (num_entries * 80 zero bytes)
    for _ in range(num_entries):
        wb(b'\x00' * 80)
    # Meta footer
    wpack('<48xI28x', 0x10000)
    # Signature
    wb(_EMPTY_SIG)

    # Write segment data
    for entry in entries:
        out[entry['offset']:entry['offset']+entry['filesz']] = entry['data']

    # Append version data if present
    if version_data:
        out += version_data

    return bytes(out)


def resign_file(src_path, log):
    """Re-sign a patched ELF back to fake SELF in-place."""
    with open(src_path, 'rb') as f:
        data = f.read()

    if data[:4] != _ELF_MAGIC:
        return "skipped_not_elf"

    try:
        fself_data = elf_to_fself(data)
    except Exception as e:
        log(f"    [!] Re-sign failed: {e}")
        return "error"

    with open(src_path, 'wb') as f:
        f.write(fself_data)

    log(f"    [✓] Re-signed ELF → FSELF ({len(data)} → {len(fself_data)} bytes)")
    return "resigned"




# ── libc.prx extra patch (recommended by BestPig for some games) ───────────
LIBC_FIND    = bytes.fromhex('e21e85d4b2db4e2c')
LIBC_REPLACE = bytes.fromhex('21620105d4c7 8ade'.replace(' ',''))

def patch_libc(game_dir, log):
    """Apply BestPig's recommended libc.prx patch for game compatibility."""
    libc_path = os.path.join(game_dir, 'sce_module', 'libc.prx')
    if not os.path.exists(libc_path):
        log("  [?] libc.prx not found — skipping")
        return False

    with open(libc_path, 'rb') as f:
        data = f.read()

    if LIBC_FIND not in data:
        log("  [?] libc.prx — patch pattern not found (may already be patched or different version)")
        return False

    count = data.count(LIBC_FIND)
    patched = data.replace(LIBC_FIND, LIBC_REPLACE)

    with open(libc_path, 'wb') as f:
        f.write(patched)

    log(f"  [✓] libc.prx patched ({count} replacement(s))")
    return True


# ── ELF imports scanner ────────────────────────────────────────────────────
# Scans eboot.bin to find which SCE libraries the game actually imports
SCE_LIB_MAP = {
    'libSceAgc':                       'libSceAgc.sprx',
    'libSceAgcDriver':                 'libSceAgcDriver.sprx',
    'libSceNpAuth':                    'libSceNpAuth.sprx',
    'libSceNpAuthAuthorizedAppDialog': 'libSceNpAuthAuthorizedAppDialog.sprx',
    'libSceSaveData':                  'libSceSaveData.native.sprx',
    'libScePsml':                      'libScePsml.sprx',
    'libSceFiber':                     'libSceFiber.sprx',
}

def scan_needed_fakelibs(game_dir, log):
    """Scan eboot.bin ELF dynamic section to find which fakelibs are needed."""
    eboot = os.path.join(game_dir, 'eboot.bin')
    if not os.path.exists(eboot):
        return None  # Can't scan

    try:
        with open(eboot, 'rb') as f:
            data = f.read()

        if data[:4] != b'\x7FELF':
            return None  # Not converted yet

        # Find PT_SCE_DYNLIBDATA segment (type 0x61000000)
        e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
        e_phnum = struct.unpack_from('<H', data, 0x38)[0]

        dynlib_off = dynlib_sz = 0
        for i in range(e_phnum):
            base = e_phoff + i * 0x38
            ptype  = struct.unpack_from('<I', data, base)[0]
            poff   = struct.unpack_from('<Q', data, base + 0x08)[0]
            pfilesz= struct.unpack_from('<Q', data, base + 0x20)[0]
            if ptype == 0x61000000:  # PT_SCE_DYNLIBDATA
                dynlib_off = poff
                dynlib_sz  = pfilesz
                break

        if not dynlib_off:
            return None

        # Search for SCE library names in the dynlib segment
        dynlib_data = data[dynlib_off:dynlib_off + dynlib_sz]
        needed = set()
        for lib_name, sprx_name in SCE_LIB_MAP.items():
            if lib_name.encode() in dynlib_data:
                needed.add(sprx_name)

        return needed
    except:
        return None

# ── Main backport orchestrator ─────────────────────────────────────────────

def run_backport(game_dir, fakelib_dir, fallback_dir, patches_dir, fw_label, log, done_cb):
    ps5_ver, ps4_ver = SDK_VERSION_PAIRS[fw_label]
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = os.path.basename(game_dir.rstrip("/\\"))
    backup_dir  = os.path.join(os.path.dirname(game_dir),
                               f"{folder_name}_Backup_{ts}")

    log("╔══════════════════════════════════════════════════")
    log(f"  PS5 MacPork")
    log(f"  Target   : {fw_label}")
    log(f"  Game     : {folder_name}")
    log(f"  Backup   : {os.path.basename(backup_dir)}")
    log("╚══════════════════════════════════════════════════\n")

    # ── STEP 0: Convert FSELF → ELF ──────────────────────────────────────
    log("─── Step 0: Converting FSELF → ELF ───────────────")

    all_candidates = [
        os.path.join(dp, fn)
        for dp, _, files in os.walk(game_dir)
        for fn in files
        if os.path.splitext(fn)[1].lower() in PATCHABLE_EXT
    ]

    fself_counts = {"converted": 0, "skipped_not_fself": 0, "error": 0}
    for fp in all_candidates:
        rel = os.path.relpath(fp, game_dir)
        with open(fp, 'rb') as f:
            magic_bytes = f.read(4)
        magic_val = struct.unpack_from('<I', magic_bytes)[0] if len(magic_bytes) >= 4 else 0
        if magic_val in (SELF_MAGIC_PS4, SELF_MAGIC_PS5):
            log(f"  Converting: {rel}")
            result = unfself_file(fp, backup_dir, game_dir, log)
            fself_counts[result] = fself_counts.get(result, 0) + 1

    log(f"  Converted: {fself_counts['converted']}  "
        f"Errors: {fself_counts['error']}  "
        f"Non-FSELF: {fself_counts['skipped_not_fself']}\n")

    # ── STEP 1: Scan imports + patch fakelib files ───────────────────────
    log("─── Step 1: Scanning imports & patching fakelibs ─")

    # Scan eboot.bin to find which fakelibs are actually needed
    needed_fakelibs = scan_needed_fakelibs(game_dir, log)
    if needed_fakelibs:
        log(f"  [✓] Game needs: {', '.join(sorted(needed_fakelibs)) or 'none detected'}")
    else:
        log("  [?] Could not scan imports — will install all available fakelibs")

    patched_fakelibs = {}  # filename → patched bytes

    # Collect available fakelibs from primary + fallback folders
    primary_files  = set(f for f in os.listdir(fakelib_dir)
                         if f.endswith(('.sprx', '.prx')))
    fallback_files = set()
    if fallback_dir and os.path.isdir(fallback_dir):
        fallback_files = set(f for f in os.listdir(fallback_dir)
                             if f.endswith(('.sprx', '.prx')))

    # Determine which files to install
    if needed_fakelibs:
        # Only install what the game needs
        to_install = needed_fakelibs
        # Find which ones we have
        available = primary_files | fallback_files
        missing = to_install - available
        if missing:
            log(f"  [?] Missing fakelibs (not in either folder): {', '.join(sorted(missing))}")
        to_install = to_install & available
    else:
        # Install everything available
        to_install = primary_files | fallback_files

    if not to_install:
        log("  [!] No fakelib files found — aborting")
        done_cb(); return

    for fname in sorted(to_install):
        # Prefer primary folder, fall back to fallback folder
        if fname in primary_files:
            src_path = os.path.join(fakelib_dir, fname)
            source_label = "primary"
        else:
            src_path = os.path.join(fallback_dir, fname)
            source_label = "fallback"

        patch_name = os.path.splitext(fname)[0] + ".bps"
        patch_path = os.path.join(patches_dir, patch_name) if patches_dir and os.path.isdir(patches_dir) else ""

        if patch_path and os.path.exists(patch_path):
            try:
                with open(src_path,   'rb') as f: src_data   = f.read()
                with open(patch_path, 'rb') as f: patch_data = f.read()
                patched_fakelibs[fname] = apply_bps(patch_data, src_data)
                log(f"  [✓] Patched: {fname} ({source_label})")
            except Exception as e:
                log(f"  [?] Patch failed for {fname} — copying as-is ({source_label})")
                with open(src_path, 'rb') as f:
                    patched_fakelibs[fname] = f.read()
        else:
            with open(src_path, 'rb') as f:
                patched_fakelibs[fname] = f.read()
            log(f"  [→] No patch — copying as-is: {fname} ({source_label})")

    # ── STEP 2: Copy patched fakelibs into game dump ──────────────────────
    log("\n─── Step 2: Installing fakelibs into game dump ───")
    dest_fakelib = os.path.join(game_dir, "fakelib")
    os.makedirs(dest_fakelib, exist_ok=True)

    # Backup existing fakelib folder if present
    if os.listdir(dest_fakelib):
        fakelib_backup = os.path.join(backup_dir, "fakelib")
        os.makedirs(fakelib_backup, exist_ok=True)
        for f in os.listdir(dest_fakelib):
            shutil.copy2(os.path.join(dest_fakelib, f),
                         os.path.join(fakelib_backup, f))
        log(f"  [→] Backed up existing fakelib folder")

    for fname, data in patched_fakelibs.items():
        dest = os.path.join(dest_fakelib, fname)
        with open(dest, 'wb') as f:
            f.write(data)
        log(f"  [✓] Installed: {fname}")

    # ── STEP 3: SDK downgrade all ELF files in game dump ─────────────────
    log("\n─── Step 3: SDK downgrade — eboot & modules ──────")

    all_files = [
        os.path.join(dp, fn)
        for dp, _, files in os.walk(game_dir)
        for fn in files
        if os.path.splitext(fn)[1].lower() in PATCHABLE_EXT
        and os.path.join(dp, fn) not in
            [os.path.join(dest_fakelib, f) for f in patched_fakelibs]
    ]

    log(f"  Found {len(all_files)} candidate file(s)\n")
    counts = {"patched":0,"skipped_signed":0,"skipped_no_param":0,
              "skipped_not_elf":0,"error":0}

    for fp in all_files:
        rel = os.path.relpath(fp, game_dir)
        log(f"  Processing: {rel}")
        result = sdk_downgrade_file(fp, backup_dir, game_dir,
                                    ps5_ver, ps4_ver, log)
        counts[result] = counts.get(result, 0) + 1
        log("")

    # ── STEP 3.5: Apply libc.prx extra patch ────────────────────────────
    log("\n─── Step 3.5: Patching libc.prx ──────────────────")
    patch_libc(game_dir, log)

    # ── STEP 4: Re-sign patched ELFs back to fake SELF ──────────────────
    log("\n─── Step 4: Re-signing ELF → fake SELF ───────────")

    resign_counts = {"resigned": 0, "skipped_not_elf": 0, "error": 0}
    for fp in all_files:
        rel = os.path.relpath(fp, game_dir)
        with open(fp, 'rb') as f:
            magic = f.read(4)
        if magic == ELF_MAGIC:
            log(f"  Signing: {rel}")
            result = resign_file(fp, log)
            resign_counts[result] = resign_counts.get(result, 0) + 1

    log(f"  Re-signed: {resign_counts['resigned']}  "
        f"Errors: {resign_counts['error']}\n")

    # ── Summary ───────────────────────────────────────────────────────────
    log("══════════════════════════════════════════════════")
    log(f"  Complete!")
    log(f"  FSELF converted    : {fself_counts['converted']}")
    log(f"  ELF files patched  : {counts['patched']}")
    log(f"  Re-signed          : {resign_counts['resigned']}")
    log(f"  Errors             : {counts['error'] + resign_counts['error']}")
    log(f"  Backup folder      : {os.path.basename(backup_dir)}")
    log("══════════════════════════════════════════════════")
    log("\n  Copy your game dump to the PS5 and run ps5-backpork.elf")
    log("  Results not guaranteed on all firmware versions.")
    log("\n  ☕ If MacPork helped you, consider buying me a coffee:")
    log("  https://ko-fi.com/macpork")

    done_cb()


# ── GUI ────────────────────────────────────────────────────────────────────

RED    = "#4199ff"
GREEN  = "#007700"
ORANGE = "#cc6600"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PS5 MacPork v1.0")
        self.resizable(True, True)
        self.minsize(700, 660)
        self.geometry("780x760")
        self._cfg = load_config()
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        main = tk.Frame(self, padx=20, pady=16)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        row = 0

        # Title
        tk.Label(main, text="PS5 MacPork  v1.0",
                 font=("Helvetica", 18, "bold"), fg=RED
                 ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0,8))
        row += 1

        # ── Folder rows ─────────────────────────────────────────────────────
        # Each tuple: (label, attr, sublabel, remember_path, initial_downloads)
        folder_defs = [
            ("Game Dump Folder:", "game_var",
             None, False, True),
            ("Primary Fakelib Folder:", "fakelib_var",
             "6.xx or 7.xx fakelibs", True, False),
            ("Fallback Fakelib Folder:", "fallback_var",
             "Optional — 4.xx fakelibs for games needing libSceFiber etc.", True, False),
            ("Patches Folder:", "patches_var",
             "Required for 6.xx/7.xx only — leave empty or any folder for 4.xx", True, False),
        ]

        for label, attr, sublabel, remember, use_downloads in folder_defs:
            setattr(self, attr, tk.StringVar())
            var = getattr(self, attr)
            # Restore saved path
            if remember and attr in self._cfg:
                var.set(self._cfg[attr])

            tk.Label(main, text=label, font=("Helvetica", 12, "bold"),
                     anchor="w"
                     ).grid(row=row, column=0, sticky="w", pady=(0,1))
            row += 1

            if sublabel:
                tk.Label(main, text=sublabel, font=("Helvetica", 9),
                         fg="gray", anchor="w"
                         ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0,2))
                row += 1

            tk.Entry(main, textvariable=var,
                     font=("Helvetica", 11), relief=tk.SUNKEN, bd=2
                     ).grid(row=row, column=0, columnspan=2, sticky="ew",
                            ipady=5, pady=(0,4))
            tk.Button(main, text="Browse…",
                      command=lambda v=var, l=label, ud=use_downloads, a=attr, r=remember:
                          self._browse(v, l, ud, a, r),
                      font=("Helvetica", 11), padx=8
                      ).grid(row=row, column=2, sticky="ew", padx=(8,0), pady=(0,4))
            row += 1
            ttk.Separator(main, orient="horizontal"
                          ).grid(row=row, column=0, columnspan=3,
                                 sticky="ew", pady=(0,10))
            row += 1

        # ── Firmware selector ────────────────────────────────────────────────
        tk.Label(main, text="Target Firmware:", font=("Helvetica", 12, "bold"),
                 anchor="w"
                 ).grid(row=row, column=0, sticky="w")
        saved_fw = self._cfg.get("fw", "FW 7.xx")
        self.fw_var = tk.StringVar(value=saved_fw)
        ttk.Combobox(main, textvariable=self.fw_var,
                     values=list(SDK_VERSION_PAIRS.keys()),
                     state="readonly", font=("Helvetica", 12), width=12
                     ).grid(row=row, column=1, sticky="w", padx=(8,0))
        self.hint = tk.Label(main, text="", font=("Courier", 10), fg="gray")
        self.hint.grid(row=row, column=2, sticky="w", padx=(8,0))
        self.fw_var.trace_add("write", self._update_hint)
        self._update_hint()
        row += 1

        ttk.Separator(main, orient="horizontal"
                      ).grid(row=row, column=0, columnspan=3,
                             sticky="ew", pady=(8,8))
        row += 1

        # ── Log ──────────────────────────────────────────────────────────────
        tk.Label(main, text="Output Log:", font=("Helvetica", 12, "bold"),
                 anchor="w"
                 ).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0,4))
        row += 1
        main.rowconfigure(row, weight=1)
        self.log = scrolledtext.ScrolledText(
            main, font=("Courier", 11), relief=tk.SUNKEN, bd=2,
            state=tk.DISABLED, wrap=tk.WORD, height=10,
            takefocus=False, highlightthickness=0)
        self.log.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=(0,12))
        self.log.tag_config("err",  foreground=RED)
        self.log.tag_config("warn", foreground=ORANGE)
        self.log.tag_config("ok",   foreground=GREEN)
        self.log.tag_config("dim",  foreground="gray")
        row += 1

        # ── Start button ─────────────────────────────────────────────────────
        self.btn = tk.Button(
            main, text="▶   Start Backport", command=self._start,
            font=("Helvetica", 14, "bold"), fg="white", bg=RED,
            activebackground="#2277cc", activeforeground="white",
            pady=10, relief=tk.FLAT)
        self.btn.grid(row=row, column=0, columnspan=3, sticky="ew")
        row += 1

        # ── Donate link ──────────────────────────────────────────────────────
        tk.Label(main, text="PS5 MacPork — Free & Open Source",
                 font=("Helvetica", 9), fg="gray", anchor="center"
                 ).grid(row=row, column=0, columnspan=2, sticky="ew", pady=(6,0))
        tk.Button(main, text="☕ Ko-fi",
                  command=lambda: webbrowser.open("https://ko-fi.com/macpork"),
                  font=("Helvetica", 9), fg="#29ABE0", relief=tk.FLAT,
                  cursor="hand2", bg=self.cget("bg")
                  ).grid(row=row, column=2, sticky="e", pady=(6,0))

    def _show_complete_popup(self):
        """Show completion popup with donate link."""
        popup = tk.Toplevel(self)
        popup.title("Backport Complete")
        popup.resizable(False, False)
        popup.grab_set()  # Modal

        # Center on parent
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - 200
        y = self.winfo_y() + (self.winfo_height() // 2) - 120
        popup.geometry(f"400x220+{x}+{y}")

        frame = tk.Frame(popup, padx=24, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="✅  Backport Complete!",
                 font=("Helvetica", 15, "bold"), fg=GREEN
                 ).pack(anchor="w", pady=(0, 8))

        tk.Label(frame, text="Your game is ready to copy to the PS5.",
                 font=("Helvetica", 12)
                 ).pack(anchor="w")

        tk.Label(frame, text="Results may vary by game and firmware version.",
                 font=("Helvetica", 10), fg="gray"
                 ).pack(anchor="w", pady=(2, 16))

        tk.Label(frame, text="☕  If MacPork helped you, buy me a coffee!",
                 font=("Helvetica", 11)
                 ).pack(anchor="w", pady=(0, 16))

        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X)

        tk.Button(btn_frame, text="☕  Ko-fi",
                  command=lambda: [webbrowser.open("https://ko-fi.com/macpork"), popup.destroy()],
                  font=("Helvetica", 12, "bold"), fg="white", bg="#29ABE0",
                  relief=tk.FLAT, padx=16, pady=6, cursor="hand2"
                  ).pack(side=tk.LEFT)

        tk.Button(btn_frame, text="Close",
                  command=popup.destroy,
                  font=("Helvetica", 12), relief=tk.FLAT,
                  padx=16, pady=6
                  ).pack(side=tk.RIGHT)

    def _browse(self, var, title, use_downloads, attr, remember):
        # Determine initial directory
        current = var.get().strip()
        if current and os.path.isdir(current):
            initial = current
        elif use_downloads:
            initial = os.path.expanduser("~/Downloads")
        elif attr in self._cfg and os.path.isdir(self._cfg.get(attr, "")):
            initial = self._cfg[attr]
        else:
            initial = os.path.expanduser("~/Downloads")

        d = filedialog.askdirectory(title=f"Select {title}", initialdir=initial)
        if d:
            var.set(d)
            if remember:
                self._cfg[attr] = d
                save_config(self._cfg)

    def _update_hint(self, *_):
        fw = self.fw_var.get()
        if fw in SDK_VERSION_PAIRS:
            p5, p4 = SDK_VERSION_PAIRS[fw]
            self.hint.config(text=f"PS5: 0x{p5:08X}  PS4: 0x{p4:08X}")
        # Save fw preference
        self._cfg["fw"] = fw
        save_config(self._cfg)

    def _append(self, msg):
        self.log.config(state=tk.NORMAL)
        tag = None
        if "[!]" in msg or "error" in msg.lower() or "abort" in msg.lower():
            tag = "err"
        elif "[?]" in msg or "skip" in msg.lower():
            tag = "warn"
        elif "[✓]" in msg or "Complete" in msg or "Installed" in msg:
            tag = "ok"
        elif msg.startswith("─") or msg.startswith("╔") or \
             msg.startswith("╚") or msg.startswith("══"):
            tag = "dim"
        self.log.insert(tk.END, msg + "\n", tag or "")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def _log(self, msg):
        self.after(0, lambda m=msg: self._append(m))

    def _done(self):
        self.after(0, lambda: self.btn.config(
            state=tk.NORMAL, text="▶   Start Backport", bg=RED))
        self.after(100, self._show_complete_popup)

    def _start(self):
        game     = self.game_var.get().strip()
        fakelib  = self.fakelib_var.get().strip()
        fallback = self.fallback_var.get().strip()
        patches  = self.patches_var.get().strip()
        fw       = self.fw_var.get()

        errors = []
        if not game   or not os.path.isdir(game):
            errors.append("[!] Game dump folder is missing or invalid")
        if not fakelib or not os.path.isdir(fakelib):
            errors.append("[!] Primary fakelib folder is missing or invalid")

        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)

        if errors:
            for e in errors: self._log(e)
            return

        # fallback and patches are optional
        fallback = fallback if fallback and os.path.isdir(fallback) else None
        patches  = patches  if patches  and os.path.isdir(patches)  else None

        self.btn.config(state=tk.DISABLED, text="⏳  Working…",
                        bg="gray", fg="white")
        threading.Thread(
            target=run_backport,
            args=(game, fakelib, fallback, patches, fw, self._log, self._done),
            daemon=True
        ).start()


if __name__ == "__main__":
    App().mainloop()
