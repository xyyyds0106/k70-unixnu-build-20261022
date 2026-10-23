"""Verify real probe text, immutable parent gates and original source POST HMAC."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from bundle_contract import (BASE_VERIFIER, PARENT_KERNEL, PARENT_MANIFEST, PROBE_SYMBOLS,
    STAGE_SYMBOLS, BOUNDARY_SYMBOLS, EARLY_PARENT_MANIFEST, EARLY_PARENT_KERNEL)

def direct_calls(code, va):
    result=[]
    for offset in range(0,len(code)-3,4):
        word=struct.unpack_from('<I',code,offset)[0]
        if word & 0xfc000000 == 0x94000000:
            immediate=word & 0x3ffffff
            if immediate & 0x2000000: immediate-=0x4000000
            result.append((offset,va+offset+immediate*4))
    return result

def branch_targets(code, va):
    return [target for offset,target in direct_calls(code,va)]+[
        va+offset+((word&0x3ffffff)-(0x4000000 if word&0x2000000 else 0))*4
        for offset in range(0,len(code)-3,4)
        for word in [struct.unpack_from('<I',code,offset)[0]] if word&0xfc000000==0x14000000]

def stage_call_order(code, va, addresses):
    """Require actual BLs, constant W0 stages, and ordered noinline boundaries."""
    calls=direct_calls(code,va)
    stages=[]
    for offset,target in calls:
        if target != addresses['_k70_xnu_usb_stage']: continue
        previous=struct.unpack_from('<I',code,offset-4)[0] if offset>=4 else 0
        if previous & 0xffe0001f != 0x52800000:
            raise ValueError('USB stage BL lacks immediate W0 selector')
        stages.append(((previous>>5)&0xffff,offset))
    if [mode for mode,offset in stages] != [1,2,3]:
        raise ValueError('Initialize must call exactly U1/U2/U3 in order')
    indices={}
    for name in ('_CheckSmmu','_AllocateDma'):
        found=[offset for offset,target in calls if target==addresses[name]]
        if len(found)!=1: raise ValueError('Missing/ambiguous Initialize boundary call: '+name)
        indices[name]=found[0]
    maps=[offset for offset,target in calls if target==addresses['_MapKernelDevices']]
    stops=[offset for offset,target in calls if target==addresses['_StopEngine']]
    # Clang duplicates the two initial map paths and inlines Fail into several
    # blocks. Early cleanup StopEngine is safe because ControllerTouched is
    # still false. Preserve those real branches; verify the normal init path.
    if not maps or max(maps)>=stages[0][1]: raise ValueError('U1 must follow every actual mapping path')
    normal_stops=[offset for offset in stops if offset>stages[2][1]]
    if not normal_stops: raise ValueError('U3 must precede normal controller StopEngine call')
    indices['_MapKernelDevices']=max(maps)
    indices['_StopEngine']=min(normal_stops)
    sequence=[indices['_MapKernelDevices'],stages[0][1],indices['_CheckSmmu'],
              stages[1][1],indices['_AllocateDma'],stages[2][1],indices['_StopEngine']]
    if sequence != sorted(sequence) or len(set(sequence)) != 7:
        raise ValueError('USB stage machine-call safety order differs')
    return {'ordered_calls':[{'name':name,'offset':offset} for name,offset in zip(
        ['MapKernelDevices','U1','CheckSmmu','U2','AllocateDma','U3','StopEngine'],sequence)],
        'stage_selectors':[1,2,3], 'mapping_call_offsets':maps,
        'untouched_failure_cleanup_stop_offsets':[offset for offset in stops if offset<stages[2][1]],
        'runtime_checkpoint_verified':False}


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
    required = PROBE_SYMBOLS+STAGE_SYMBOLS+BOUNDARY_SYMBOLS+['_k70_xnu_after_vm','_ml_io_map']
    for i in range(nsyms):
        strx, typ, sect, desc, value = struct.unpack_from('<IBBHQ', data, symoff+16*i)
        if typ & 0xe0 or typ & 0x0e != 0x0e or not sect:
            continue
        values.append((sect, value))
        end = data.index(b'\0', stroff+strx, stroff+strbytes)
        name = data[stroff+strx:end].decode()
        if name in required:
            if name in probes or sect > len(sections):
                raise ValueError('Ambiguous/out-of-range probe symbol: '+name)
            probes[name] = (sect, value)
    if set(probes) != set(required):
        raise ValueError('Missing actual noinline USB-stage symbols: '+repr(sorted(set(required)-set(probes))))
    bounded = {}
    code_by_name = {}
    for name in required:
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
    result['early_probe_helpers'] = {name:bounded[name] for name in PROBE_SYMBOLS}
    result['early_probe_parent_source_manifest_sha256'] = EARLY_PARENT_MANIFEST
    result['early_probe_parent_kernel_sha256'] = EARLY_PARENT_KERNEL
    result['early_probe_runtime_checkpoint_or_reset_verified'] = False
    addresses={name:value for name,(sect,value) in probes.items()}
    order=stage_call_order(code_by_name['_K70UsbCdcInitialize'],addresses['_K70UsbCdcInitialize'],addresses)
    for caller,callee in [('_k70_xnu_after_vm','_K70UsbCdcInitialize'),
            ('_k70_xnu_usb_stage','_k70_xnu_usb_stage_reset'),
            ('_k70_xnu_usb_stage_reset','_k70_probe_reset_core'),
            ('_k70_xnu_probe','_k70_probe_reset_core'),
            ('_k70_probe_reset_core','_k70_probe_wait'),
            ('_k70_probe_reset_core','_k70_probe_psci')]:
        if addresses[callee] not in branch_targets(code_by_name[caller],addresses[caller]):
            raise ValueError('Missing actual USB-stage reset/init call: '+caller+' -> '+callee)
    map_calls=direct_calls(code_by_name['_MapKernelDevices'],addresses['_MapKernelDevices'])
    if sum(target==addresses['_ml_io_map'] for offset,target in map_calls)!=4:
        raise ValueError('U1 mapping boundary lacks exactly four actual ml_io_map calls')
    for marker in (b'K70USBSTAGE version=1 boot=',b'k70_usb_stage',b'controller_touched=%u',
                   b'U1 probe returned; controller untouched',b'U2 probe returned; controller untouched',
                   b'U3 probe returned; controller untouched'):
        if marker not in data: raise ValueError('Missing USB initialization stage marker: '+repr(marker))
    result.update(usb_stage_version=1,usb_stage_symbols_verified=list(STAGE_SYMBOLS),
        usb_stage_helpers={name:bounded[name] for name in STAGE_SYMBOLS+BOUNDARY_SYMBOLS},
        usb_stage_initialization_order=order,
        usb_stage_parent_source_manifest_sha256=PARENT_MANIFEST,
        usb_stage_parent_kernel_sha256=PARENT_KERNEL,
        usb_stage_runtime_checkpoint_or_reset_verified=False)
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
