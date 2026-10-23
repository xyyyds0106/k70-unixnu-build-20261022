"""Verify real probe text, immutable parent gates and original source POST HMAC."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from bundle_contract import BASE_VERIFIER, PARENT_KERNEL, PARENT_MANIFEST, PROBE_SYMBOLS


def verify(kernel, hmac):
    parent_checker = Path(__file__).with_name('base_verify_kernel.py')
    if hashlib.sha256(parent_checker.read_bytes()).hexdigest() != BASE_VERIFIER:
        raise ValueError('Frozen parent executable/HMAC verifier mismatch')
    spec = importlib.util.spec_from_file_location('probe_parent_verifier', parent_checker)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.verify(kernel, hmac)
    data = kernel.read_bytes()
    # The inherited verifier authenticates actual Mach-O sections, executable
    # controls and POST HMAC. Independently parse only the additional symbols.
    sections = []
    table = None
    pos = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, pos)
        if cmd == 0x19:
            prot, count = struct.unpack_from('<II', data, pos+60)
            for i in range(count):
                off = pos+72+80*i
                va, nbytes = struct.unpack_from('<QQ', data, off+32)
                foff = struct.unpack_from('<I', data, off+48)[0]
                flags = struct.unpack_from('<I', data, off+64)[0]
                sections.append((va, nbytes, foff, prot, flags & 255))
        elif cmd == 2:
            table = struct.unpack_from('<4I', data, pos+8)
        pos += size
    symoff, nsyms, stroff, strbytes = table
    values, probes = [], {}
    for i in range(nsyms):
        strx, typ, sect, desc, value = struct.unpack_from('<IBBHQ', data, symoff+16*i)
        if typ & 0xe0 or typ & 0x0e != 0x0e or not sect:
            continue
        values.append((sect, value))
        end = data.index(b'\0', stroff+strx, stroff+strbytes)
        name = data[stroff+strx:end].decode()
        if name in PROBE_SYMBOLS:
            if name in probes or sect > len(sections):
                raise ValueError('Ambiguous/out-of-range probe symbol: '+name)
            probes[name] = (sect, value)
    if set(probes) != set(PROBE_SYMBOLS):
        raise ValueError('Missing actual noinline probe symbols')
    bounded = {}
    code_by_name = {}
    for name in PROBE_SYMBOLS:
        sect, value = probes[name]
        va, nbytes, foff, prot, kind = sections[sect-1]
        end = min([v for s,v in values if s == sect and v > value]+[va+nbytes])
        length = end-value
        offset = foff+value-va
        if not prot & 4 or kind != 0 or value < va or not 4 <= length <= 65536 or offset+length > len(data):
            raise ValueError('Probe symbol is not bounded executable code: '+name)
        code = data[offset:offset+length]
        code_by_name[name] = code
        bounded[name] = {'va':value, 'bytes':length, 'sha256':hashlib.sha256(code).hexdigest()}
    psci = code_by_name['_k70_probe_psci']
    if struct.pack('<I',0xd4000003) not in psci or struct.pack('<I',0xd4000002) not in psci:
        raise ValueError('Independent probe helper lacks actual SMC and HVC')
    wait = code_by_name['_k70_probe_wait']
    words = [struct.unpack_from('<I',wait,i)[0] for i in range(0,len(wait)-3,4)]
    # MRS Rt,CNTPCT_EL0 and MRS Rt,CNTFRQ_EL0, allowing any destination GPR.
    if not any(w & ~31 == 0xd53be020 for w in words) or not any(w & ~31 == 0xd53be000 for w in words):
        raise ValueError('Bounded wait helper lacks actual architectural counter/frequency reads')
    for marker in (b'K70PROBE version=1 boot=', b'k70_probe', b'counter-or-iteration-failed',
                   b'reset-returned-normal-flow', b'source=adt:/psci', b'delay_ms=4000'):
        if marker not in data:
            raise ValueError('Missing actual early-probe marker: '+repr(marker))
    result['early_probe_version'] = 1
    result['early_probe_symbols_verified'] = list(PROBE_SYMBOLS)
    result['early_probe_helpers'] = bounded
    result['early_probe_parent_source_manifest_sha256'] = PARENT_MANIFEST
    result['early_probe_parent_kernel_sha256'] = PARENT_KERNEL
    result['early_probe_runtime_checkpoint_or_reset_verified'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--hmac', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.kernel, args.hmac), indent=2)+'\n'
    if args.output:
        args.output.write_text(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
