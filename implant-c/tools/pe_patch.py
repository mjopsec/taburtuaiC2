#!/usr/bin/env python3
"""
pe_patch.py — Post-build PE masquerade patcher.

Actions:
  1. Zero the Rich header (MSVC/MinGW linker toolchain fingerprint).
  2. Patch the COFF TimeDateStamp to a random plausible date in the
     Windows 10/11 binary era (2021-01-01 to 2024-06-01 UTC).

Usage: python3 pe_patch.py <pe_file>
"""

import sys
import os
import struct
import random


def patch_pe(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 0x40:
        print(f'[!] pe_patch: file too small ({len(data)} bytes), skipping')
        return

    # ── Read e_lfanew ────────────────────────────────────────────────────────
    if data[0:2] != b'MZ':
        print('[!] pe_patch: not a PE/MZ file, skipping')
        return
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        print('[!] pe_patch: e_lfanew out of bounds, skipping')
        return
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print('[!] pe_patch: PE signature not found at e_lfanew, skipping')
        return

    # ── 1. Zero the Rich header ──────────────────────────────────────────────
    # The Rich header lives between the DOS stub (after 0x40) and the PE header.
    # It ends with the 4-byte "Rich" signature followed by a 4-byte checksum.
    rich_sig  = b'Rich'
    dans_magic = 0x536E6144   # "DanS" little-endian

    rich_pos = -1
    search_end = min(e_lfanew, len(data) - 8)
    for i in range(0x40, search_end):
        if data[i:i+4] == rich_sig:
            rich_pos = i
            break

    if rich_pos >= 0:
        checksum = struct.unpack_from('<I', data, rich_pos + 4)[0]
        dans_xored = checksum ^ dans_magic
        dans_pos = -1
        for i in range(0x40, rich_pos):
            if struct.unpack_from('<I', data, i)[0] == dans_xored:
                dans_pos = i
                break

        if dans_pos >= 0:
            zero_end = rich_pos + 8  # include "Rich" + 4-byte checksum
            for i in range(dans_pos, zero_end):
                data[i] = 0
            print(f'[+] pe_patch: Rich header zeroed '
                  f'({dans_pos:#06x}–{zero_end:#06x}, {zero_end - dans_pos} bytes)')
        else:
            print('[!] pe_patch: Rich header found but DanS start not located, skipping')
    else:
        print('[*] pe_patch: no Rich header found (already clean)')

    # ── 2. Patch COFF TimeDateStamp ──────────────────────────────────────────
    # COFF FileHeader layout at e_lfanew + 4:
    #   Machine(2) | NumberOfSections(2) | TimeDateStamp(4)
    ts_offset = e_lfanew + 4 + 4   # skip "PE\0\0" + Machine + NumSections
    if ts_offset + 4 <= len(data):
        # Random Unix timestamp: 2021-01-01T00:00:00Z … 2024-06-01T00:00:00Z
        ts = random.randint(1_609_459_200, 1_717_200_000)
        struct.pack_into('<I', data, ts_offset, ts)
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d')
        print(f'[+] pe_patch: TimeDateStamp → {ts:#010x}  ({dt})')
    else:
        print('[!] pe_patch: TimeDateStamp offset out of bounds')

    with open(path, 'wb') as f:
        f.write(data)
    print(f'[+] pe_patch: wrote {len(data)} bytes → {path}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: pe_patch.py <pe_file>', file=sys.stderr)
        sys.exit(1)
    patch_pe(sys.argv[1])
