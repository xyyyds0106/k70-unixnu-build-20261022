#!/usr/bin/env python3
"""Verify real linked kernel hooks, owned BSS DMA, source POST/HMAC identity.

This does not execute a kernel or treat a link as hardware success. It also
does not modify/reseal the kernel or replace the source crypto POST.
"""
import argparse
import hashlib
import hmac as hmac_module
import json
from pathlib import Path
import struct


def verify(kernel, hmac):
    data = kernel.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xFEEDFACF, 0x100000C, 0, 2):
        raise ValueError('Expected ordinary ARM64 MH_EXECUTE source kernel')
    count, command_bytes = struct.unpack_from('<II', data, 16)
    end = 32+command_bytes
    if end > len(data):
        raise ValueError('Load commands outside file')
    pos = 32
    sections, segments, symbols = [], [], {}
    symbol_addresses = []
    control_symbols = ('_control_receive', '_control_service', '_control_psci')
    symtab = None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or pos+size > end:
            raise ValueError('Invalid load command bounds')
        if cmd == 0x19:
            if size < 72:
                raise ValueError('Short LC_SEGMENT_64')
            name = data[pos+8:pos+24].rstrip(b'\0').decode()
            va, vbytes, foff, fbytes = struct.unpack_from('<4Q', data, pos+24)
            maxprot, prot, nsec = struct.unpack_from('<3I', data, pos+56)
            if size != 72+80*nsec or foff+fbytes > len(data) or va+vbytes > 1 << 64:
                raise ValueError('Invalid segment bounds')
            segments.append({'name': name, 'va': va, 'bytes': vbytes, 'prot': prot})
            for i in range(nsec):
                off = pos+72+80*i
                secname = data[off:off+16].rstrip(b'\0').decode()
                secva, secbytes = struct.unpack_from('<2Q', data, off+32)
                secoff, align, reloff, nreloc, flags = struct.unpack_from('<5I', data, off+48)
                if secva < va or secva+secbytes > va+vbytes:
                    raise ValueError('Section outside segment')
                sections.append({'name': name+','+secname, 'va': secva, 'bytes': secbytes,
                                 'file_offset': secoff,
                                 'prot': prot, 'align': align, 'kind': flags & 0xFF})
        elif cmd == 2:
            if size != 24 or symtab is not None:
                raise ValueError('Unexpected symbol table')
            symtab = struct.unpack_from('<4I', data, pos+8)
        pos += size
    if pos != end or symtab is None:
        raise ValueError('Missing or inconsistent load commands/symbol table')
    symoff, nsyms, stroff, strbytes = symtab
    if symoff+nsyms*16 > len(data) or stroff+strbytes > len(data):
        raise ValueError('Symbol table out of bounds')
    for i in range(nsyms):
        strx, typ, sect, desc, value = struct.unpack_from('<IBBHQ', data, symoff+16*i)
        if (typ & 0xE0) or (typ & 0x0E) != 0xE or not sect:
            continue
        if strx >= strbytes:
            raise ValueError('Symbol string offset out of bounds')
        name_end = data.find(b'\0', stroff+strx, stroff+strbytes)
        if name_end < 0:
            raise ValueError('Unterminated symbol')
        name = data[stroff+strx:name_end].decode(errors='strict')
        symbol_addresses.append((sect,value))
        if name.startswith('_k70_xnu_') or name in ('_kernel_dma', '_source_corecrypto14_bootstrap',
                                                   '_source_pthread_bootstrap')+control_symbols:
            if name in symbols:
                raise ValueError('Ambiguous required symbol: '+name)
            if sect > len(sections):
                raise ValueError('Symbol section out of bounds')
            symbols[name] = {'va': value, 'section': sections[sect-1]}
    for name in ('_k70_xnu_early', '_k70_xnu_after_vm', '_k70_xnu_thread_start',
                 '_k70_xnu_write', '_source_corecrypto14_bootstrap', '_source_pthread_bootstrap',
                 '_kernel_dma')+control_symbols:
        if name not in symbols:
            raise ValueError('Missing real linked symbol: '+name)
    for name in control_symbols:
        item=symbols[name]; section=item['section']
        if not section['prot'] & 4 or section['kind']!=0 or not section['va']<=item['va']<section['va']+section['bytes']:
            raise ValueError('Control symbol is not real executable text: '+name)
    psci=symbols['_control_psci']; psci_section=psci['section']
    section_id=sections.index(psci_section)+1
    psci_end=min([v for s,v in symbol_addresses if s==section_id and v>psci['va']]+
                 [psci_section['va']+psci_section['bytes']])
    psci_offset=psci_section['file_offset']+psci['va']-psci_section['va']
    psci_bytes=psci_end-psci['va']
    if not 4<=psci_bytes<=4096 or psci_offset+psci_bytes>len(data):
        raise ValueError('Invalid real PSCI helper bounds')
    psci_code=data[psci_offset:psci_offset+psci_bytes]
    if struct.pack('<I',0xd4000003) not in psci_code or struct.pack('<I',0xd4000002) not in psci_code:
        raise ValueError('Real PSCI helper lacks expected SMC/HVC instructions')
    dma = symbols['_kernel_dma']
    section = dma['section']
    if dma['va'] & 0x3FFF or not (section['prot'] & 2) or section['kind'] != 1:
        raise ValueError('DMA is not aligned, writable, permanent zero-fill image storage')
    if dma['va'] < section['va'] or dma['va']+0x4000 > section['va']+section['bytes']:
        raise ValueError('DMA span outside its image section')
    seal = json.loads(hmac.read_text())
    if seal.get('kernel_sha256') != sha:
        raise ValueError('Source POST HMAC report identifies a different kernel')
    code = next((s for s in sections if s['name'] in ('__TEXT,__text', '__TEXT_EXEC,__text')), None)
    integrity = [s for s in sections if s['name'].split(',')[1] == '__fips_hmacs']
    if code is None or len(integrity) != 1 or integrity[0]['bytes'] != 32:
        raise ValueError('Missing source-provider code or exact POST HMAC section')
    codeoff, codesize = code['file_offset'], code['bytes']
    macoff = integrity[0]['file_offset']
    textbase = next(s['va'] for s in segments if s['name'] == '__TEXT')
    if codeoff+codesize > len(data) or macoff+32 > len(data) or code['va']-textbase != codeoff:
        raise ValueError('POST source-provider text contract/bounds mismatch')
    if codeoff <= macoff < codeoff+codesize:
        raise ValueError('POST HMAC field overlaps its hashed code')
    expected_mac = hmac_module.digest(b'\0', data[codeoff:codeoff+codesize], 'sha256')
    if data[macoff:macoff+32] != expected_mac or seal.get('hmac_sha256') != expected_mac.hex():
        raise ValueError('Real source-provider POST HMAC mismatch')
    if int(seal['code_file_offset'], 0) != codeoff or seal['code_bytes'] != codesize or int(seal['hmac_file_offset'], 0) != macoff:
        raise ValueError('HMAC report offsets differ from the actual Mach-O')
    for marker in (b'K70XNU001', b'arm_vm_init returned; starting kernel-owned USB',
                   b'PE_init_platform(FALSE) returned; XNU C is executing',
                   b'K70CTL READY version=1 boot=', b'K70CTL R id=',
                   b'reboot-arm', b'reboot-confirm', b'ack-drain-timeout'):
        if marker not in data:
            raise ValueError('Kernel is missing transport/checkpoint strings')
    nonempty = [s for s in segments if s['bytes']]
    base = min(s['va'] for s in nonempty)
    top = max(s['va']+s['bytes'] for s in nonempty)
    return {'schema_version': 1, 'kernel_sha256': sha, 'bytes': len(data),
            'symbols': symbols, 'image_va_base': base, 'image_va_bytes': top-base,
            'dma_image_offset': dma['va']-base,
            'dma_bytes': 0x4000, 'serial': 'K70XNU001',
            'control_protocol': 1, 'control_symbols_verified': list(control_symbols),
            'psci_helper': {'va': psci['va'], 'bytes': psci_bytes,
                            'sha256': hashlib.sha256(psci_code).hexdigest(),
                            'smc_hvc_instructions_present': True,
                            'runtime_conduit_and_features_verified': False},
            'hmac_report_sha256': hashlib.sha256(hmac.read_bytes()).hexdigest(),
            'post_hmac_verified': True, 'runtime_selftests_executed': False,
            'scope': 'linked image and real source POST HMAC only; hardware execution unproven'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--hmac', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(verify(args.kernel, args.hmac), indent=2)+'\n'
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
