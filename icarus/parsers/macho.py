"""
Mach-O reader — architecture and embedded code-signature entitlements.

Pure-Python, standard-library only. Reads just the header, load commands,
and the code-signature LINKEDIT region (via seeks), so it scales to a full
iOS/macOS root filesystem without loading whole binaries into memory.

Validated against real iOS 26.x system daemons.
"""

import plistlib
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Tuple

from icarus.parsers.base import BaseParser

# Thin Mach-O magics -> (byte order, word size). Keyed on the first 4 bytes.
_MH_MAGICS: Dict[bytes, Tuple[Literal["little", "big"], int]] = {
    b"\xcf\xfa\xed\xfe": ("little", 64),  # MH_MAGIC_64, little-endian
    b"\xfe\xed\xfa\xcf": ("big", 64),     # MH_MAGIC_64, big-endian
    b"\xce\xfa\xed\xfe": ("little", 32),  # MH_MAGIC, little-endian
    b"\xfe\xed\xfa\xce": ("big", 32),     # MH_MAGIC, big-endian
}
_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"

# Any first-4-bytes value that marks a Mach-O (thin or fat).
MACHO_MAGICS = frozenset(_MH_MAGICS) | {_FAT_MAGIC, _FAT_MAGIC_64}

_LC_CODE_SIGNATURE = 0x1D
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02

_CPU_ARCH_ABI64 = 0x01000000
_CPU_TYPE_ARM = 12
_CPU_TYPE_X86 = 7
_CPU_SUBTYPE_ARM64E = 2

# Cap the code-signature region we will read (defends against corrupt sizes).
_MAX_SIG_BYTES = 16 * 1024 * 1024


def is_macho_magic(head: bytes) -> bool:
    """True if the first bytes are a Mach-O (thin or fat) magic."""
    return head[:4] in MACHO_MAGICS


def _u32(buf: bytes, off: int, endian: Literal["little", "big"]) -> int:
    return int.from_bytes(buf[off:off + 4], endian)


def _arch_name(cputype: int, cpusub: int) -> str:
    if cputype == (_CPU_TYPE_ARM | _CPU_ARCH_ABI64):
        return "arm64e" if (cpusub & 0xFF) == _CPU_SUBTYPE_ARM64E else "arm64"
    if cputype == (_CPU_TYPE_X86 | _CPU_ARCH_ABI64):
        return "x86_64"
    if cputype == _CPU_TYPE_ARM:
        return "arm"
    if cputype == _CPU_TYPE_X86:
        return "x86"
    return f"cpu_{cputype:#x}"


def _parse_codesig(sig: bytes):
    """Parse a code-signature SuperBlob (big-endian). Return (entitlements, flags)."""
    ents: Optional[Dict[str, Any]] = None
    flags: Optional[int] = None
    if len(sig) < 12 or _u32(sig, 0, "big") != _CSMAGIC_EMBEDDED_SIGNATURE:
        return ents, flags
    count = _u32(sig, 8, "big")
    for i in range(count):
        idx = 12 + i * 8
        if idx + 8 > len(sig):
            break
        blob_off = _u32(sig, idx + 4, "big")
        if blob_off + 8 > len(sig):
            continue
        magic = _u32(sig, blob_off, "big")
        length = _u32(sig, blob_off + 4, "big")
        if magic == _CSMAGIC_EMBEDDED_ENTITLEMENTS:
            xml = sig[blob_off + 8:blob_off + length]
            try:
                parsed = plistlib.loads(xml)
                if isinstance(parsed, dict):
                    ents = parsed
            except Exception:
                pass
        elif magic == _CSMAGIC_CODEDIRECTORY and blob_off + 16 <= len(sig):
            flags = _u32(sig, blob_off + 12, "big")
    return ents, flags


def _parse_thin(
    f,
    base: int,
    endian: Literal["little", "big"],
    bits: int,
    slice_size: int,
) -> Optional[Dict[str, Any]]:
    header_size = 32 if bits == 64 else 28
    if slice_size < header_size:
        return None
    f.seek(base)
    hdr = f.read(header_size)
    if len(hdr) < header_size:
        return None
    cputype = _u32(hdr, 4, endian)
    cpusub = _u32(hdr, 8, endian)
    ncmds = _u32(hdr, 16, endian)
    sizeofcmds = _u32(hdr, 20, endian)
    lc_start = base + header_size
    if sizeofcmds <= 0 or sizeofcmds > 8 * 1024 * 1024:
        return {"arch": _arch_name(cputype, cpusub), "entitlements": None, "code_sign_flags": None}
    if sizeofcmds > slice_size - header_size:
        return {"arch": _arch_name(cputype, cpusub), "entitlements": None, "code_sign_flags": None}
    f.seek(lc_start)
    lcs = f.read(sizeofcmds)

    ents: Optional[Dict[str, Any]] = None
    flags: Optional[int] = None
    off = 0
    for _ in range(ncmds):
        if off + 8 > len(lcs):
            break
        cmd = _u32(lcs, off, endian)
        cmdsize = _u32(lcs, off + 4, endian)
        if cmd == _LC_CODE_SIGNATURE and off + 16 <= len(lcs):
            dataoff = _u32(lcs, off + 8, endian)
            datasize = _u32(lcs, off + 12, endian)
            if (
                0 < datasize <= _MAX_SIG_BYTES
                and dataoff <= slice_size
                and datasize <= slice_size - dataoff
            ):
                f.seek(base + dataoff)
                ents, flags = _parse_codesig(f.read(datasize))
        if cmdsize == 0:
            break
        off += cmdsize
    return {"arch": _arch_name(cputype, cpusub), "entitlements": ents, "code_sign_flags": flags}


def _parse_fat(f, head: bytes, file_size: int) -> Optional[Dict[str, Any]]:
    f.seek(0)
    hdr = f.read(8)
    nfat = _u32(hdr, 4, "big")
    wide = head == _FAT_MAGIC_64
    entry_size = 32 if wide else 20
    if nfat <= 0 or nfat > 64:
        return None
    entries = f.read(nfat * entry_size)
    best: Optional[Dict[str, Any]] = None
    for i in range(nfat):
        e = entries[i * entry_size:(i + 1) * entry_size]
        if len(e) < entry_size:
            break
        offset = (int.from_bytes(e[8:16], "big") if wide
                  else int.from_bytes(e[8:12], "big"))
        size = (int.from_bytes(e[16:24], "big") if wide
                else int.from_bytes(e[12:16], "big"))
        if size < 4 or offset > file_size or size > file_size - offset:
            continue
        f.seek(offset)
        m = f.read(4)
        if m in _MH_MAGICS:
            endian, bits = _MH_MAGICS[m]
            info = _parse_thin(f, offset, endian, bits, size)
            if info and (best is None or info["arch"].startswith("arm64")):
                best = info
    return best


def macho_info(path: Path) -> Optional[Dict[str, Any]]:
    """Return {arch, entitlements, code_sign_flags} for a Mach-O, else None.

    Never raises — returns None on any read/parse failure. For fat binaries,
    prefers the arm64/arm64e slice.
    """
    try:
        with BaseParser._open_regular(path) as f:
            head = f.read(4)
            if len(head) < 4:
                return None
            f.seek(0, 2)
            file_size = f.tell()
            if head in (_FAT_MAGIC, _FAT_MAGIC_64):
                return _parse_fat(f, head, file_size)
            if head in _MH_MAGICS:
                endian, bits = _MH_MAGICS[head]
                return _parse_thin(f, 0, endian, bits, file_size)
            return None
    except (OSError, PermissionError, ValueError, IndexError):
        return None
