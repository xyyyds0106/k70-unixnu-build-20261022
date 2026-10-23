#!/usr/bin/env python3
"""Read-only validation of the pinned CI kernel and DarwinBoot layout contract."""
import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bundle_contract import validate as validate_probe_bundle, PARENT_MANIFEST, PARENT_KERNEL, PROBE_SYMBOLS, STAGE_SYMBOLS, KIND

EXPECTED = 'f12e6c8895055a12abcc2c7578823a079e4b3a749a5252877b6b29b95e06a659'
WINDOW = 0x10000000
U64 = (1 << 64) - 1
REFS = {'unixnu': 'b6ae99c17194e6a18fd819d3148e69fe405e91fc',
        'device': 'd4dbb3683023a17bb468b9774f52c87f3060e739',
        'xnu': 'd8b80295118ef25ac3a784134bcf95cd8e88109f'}
USB_SYMBOLS = {'_k70_xnu_early', '_k70_xnu_after_vm', '_k70_xnu_putc', '_k70_xnu_write', '_k70_xnu_thread_start'}
CONTROL_SYMBOLS = ['_control_receive', '_control_service', '_control_psci']


def checked_usb_manifest(path, kernel):
    """Accept the new CI kernel only with its exact source/evidence provenance.

    The local reviewed bundle is an independent input, not a digest supplied by
    the artifact itself. No arbitrary expected-hash/skip-validation flag exists.
    """
    manifest = json.loads(path.read_text())
    if manifest.get('schema_version') != 1 or manifest.get('kind') != KIND or manifest.get('base_refs') != REFS:
        raise ValueError('Unsupported USB kernel manifest or source pins')
    if path.resolve().parent != kernel.resolve().parent or manifest.get('kernel_file') != kernel.name:
        raise ValueError('Manifest and kernel must be adjacent and identify the same plain filename')
    digest = manifest.get('kernel_sha256', '')
    if not re.fullmatch('[0-9a-f]{64}', digest) or manifest.get('kernel_bytes') != kernel.stat().st_size:
        raise ValueError('Bad USB kernel digest or length')
    bundle = Path(__file__).resolve().parents[2] / 'sources/K70XnuUsbStages'
    validate_probe_bundle(bundle, Path(__file__).resolve().parent)
    if type(manifest.get('early_probe_version')) is not int or manifest['early_probe_version'] != 1 or manifest.get('early_probe_symbols') != PROBE_SYMBOLS:
        raise ValueError('CI must bind the exact early-probe protocol and symbols')
    if type(manifest.get('usb_stage_version')) is not int or manifest['usb_stage_version'] != 1 or manifest.get('usb_stage_symbols') != STAGE_SYMBOLS:
        raise ValueError('CI must bind the exact USB-stage version and symbols')
    if manifest.get('parent_source_manifest_sha256') != PARENT_MANIFEST or manifest.get('parent_kernel_sha256') != PARENT_KERNEL:
        raise ValueError('CI early-probe parent chain mismatch')
    raw = (bundle / 'source-manifest.json').read_bytes()
    local = json.loads(raw)
    if local != manifest.get('usb_bundle_manifest') or hashlib.sha256(raw).hexdigest() != manifest.get('usb_bundle_manifest_sha256'):
        raise ValueError('CI USB source manifest differs from the independent local reviewed bundle')
    if {key: local.get(key + '_commit') for key in REFS} != REFS or local.get('serial') != 'K70XNU001':
        raise ValueError('Local USB bundle source pins/identity changed')
    for relative, expected in local['files'].items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or '..' in relative_path.parts or hashlib.sha256((bundle / relative_path).read_bytes()).hexdigest() != expected:
            raise ValueError('Reviewed USB source file mismatch: ' + relative)
    if manifest.get('patch_sha256') != local['files']['zzzz-k70-usb-log.patch']:
        raise ValueError('CI patch differs from the reviewed USB patch')
    control = local.get('control')
    control_enabled = isinstance(control, dict) and type(control.get('version')) is int and control['version'] == 1
    if control is not None and not control_enabled:
        raise ValueError('Unsupported local USB control contract')
    if control_enabled:
        if type(manifest.get('control_protocol')) is not int or manifest['control_protocol'] != 1:
            raise ValueError('CI control protocol must match the reviewed K70CTL/1 bundle')
        if manifest.get('control_symbols') != CONTROL_SYMBOLS:
            raise ValueError('CI control symbols must exactly match the reviewed implementation')
    elif manifest.get('control_protocol') is not None or manifest.get('control_symbols') is not None:
        raise ValueError('CI advertises controls without a reviewed local control contract')
    required = {'build-report.json', 'crypto-hmac.json', 'SHA256SUMS', 'symbols.txt'}
    if control_enabled:
        required.add('kernel-validation.json')
    if not isinstance(manifest.get('evidence_files'), dict) or set(manifest['evidence_files']) != required:
        raise ValueError('Incomplete CI evidence-file set')
    for name, expected in manifest['evidence_files'].items():
        if hashlib.sha256((path.parent / name).read_bytes()).hexdigest() != expected:
            raise ValueError('CI evidence digest mismatch: ' + name)
    build = json.loads((path.parent / 'build-report.json').read_text())
    if build.get('sha256') != digest or build.get('bytes') != manifest['kernel_bytes'] or build.get('unixnu_commit') != REFS['unixnu'] or build.get('xnu_commit') != REFS['xnu'] or build.get('profile') != 'platform' or build.get('prelinked') is not False or build.get('vermeer_platform_cpu_drivers_linked') is not True:
        raise ValueError('CI build report does not describe the pinned ordinary platform source kernel')
    configuration = build['configuration']
    panic_region = configuration.get('XNU_DT_PANIC_REGION')
    if not (panic_region is True or type(panic_region) is int and panic_region == 1):
        raise ValueError('XNU_DT_PANIC_REGION must be enabled; reject the known BCM panic-buffer mapping profile')
    if configuration.get('XNU_CRYPTO_BOOTSTRAP') != 'source' or configuration.get('XNU_SOURCE_CORECRYPTO14') is not True or configuration.get('XNU_SOURCE_PTHREAD') is not True:
        raise ValueError('Source crypto/pthread build policy changed')
    for key in ('XNU_NATIVE_UFS', 'XNU_NATIVE_RAM_BLOCK', 'XNU_NATIVE_VIRTIO_BLOCK', 'XNU_OWNER_DATA_MOUNT', 'XNU_OWNER_UNION_SYSTEMOS'):
        if configuration.get(key) is not False:
            raise ValueError('Minimal source-kernel storage policy changed: ' + key)
    crypto = json.loads((path.parent / 'crypto-hmac.json').read_text())
    if crypto.get('kernel_sha256') != digest or crypto.get('runtime_selftests_executed') is not False:
        raise ValueError('HMAC evidence describes another kernel or overclaims runtime tests')
    sums = (path.parent / 'SHA256SUMS').read_text().splitlines()
    expected_sum = [(match[1], match[2]) for line in sums if (match := re.fullmatch(r'([0-9a-f]{64})\s+\*?(.+)', line))]
    if expected_sum != [(digest, kernel.name)]:
        raise ValueError('SHA256SUMS must identify exactly this kernel')
    ci = manifest.get('ci', {})
    if ci.get('repository') != 'xyyyds0106/k70-unixnu-build-20261022' or not str(ci.get('run_id', '')).isdigit() or not re.fullmatch('[0-9a-f]{40}', ci.get('commit', '')):
        raise ValueError('Unexpected CI repository/run/commit provenance')
    validation = None
    if control_enabled:
        # Recompute the real Mach-O, executable control symbols/SMC/HVC and
        # source POST HMAC contract. A hash-bound report is not trusted as an
        # assertion without this independent local verifier execution.
        checker = Path(__file__).resolve().parent / 'verify_kernel.py'
        spec = importlib.util.spec_from_file_location('k70_real_control_kernel_verifier', checker)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        validation = verifier.verify(kernel, path.parent / 'crypto-hmac.json')
        bound = json.loads((path.parent / 'kernel-validation.json').read_text())
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        if canonical(validation) != canonical(bound):
            raise ValueError('Bound CI kernel-validation report differs from recomputed actual kernel evidence')
        if validation.get('kernel_sha256') != digest or validation.get('control_protocol') != 1 or validation.get('control_symbols_verified') != CONTROL_SYMBOLS:
            raise ValueError('Actual kernel control evidence differs from its CI identity')
    return {'expected_sha256': digest, 'manifest_path': str(path), 'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'usb_bundle_manifest_sha256': manifest['usb_bundle_manifest_sha256'], 'usb_patch_sha256': manifest['patch_sha256'],
            'base_refs': REFS, 'ci': ci, 'crypto_evidence': crypto,
            'control_protocol': 1 if control_enabled else None,
            'control_symbols': CONTROL_SYMBOLS if control_enabled else [],
            'kernel_validation_sha256': manifest['evidence_files'].get('kernel-validation.json'),
            'recomputed_kernel_validation': validation}


def inspect(path, kernel_manifest=None):
    if kernel_manifest is None:
        raise ValueError('A new USB-stage kernel requires its bound CI manifest')
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    provenance = checked_usb_manifest(kernel_manifest, path) if kernel_manifest else None
    expected = provenance['expected_sha256'] if provenance else EXPECTED
    if digest != expected:
        raise ValueError('Not the reviewed unmodified platform CI kernel')
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Not ordinary ARM64 subtype 0 MH_EXECUTE')
    count, command_bytes = struct.unpack_from('<II', data, 16)
    if count > 1024 or command_bytes > len(data) - 32:
        raise ValueError('Invalid load-command bounds')
    offset, end = 32, 32 + command_bytes
    segments, sections, entry, symtab = [], [], None, None
    for _ in range(count):
        if end - offset < 8:
            raise ValueError('Truncated load command')
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or size % 8 or size > end - offset:
            raise ValueError('Bad load-command size')
        if command == 0x19:
            if size < 72:
                raise ValueError('Short segment command')
            name, va, length, fileoff, filebytes, maxprot, prot, nsects, _ = struct.unpack_from('<16s4Q4I', data, offset + 8)
            if nsects > (size - 72) // 80 or length > WINDOW or va > U64 - length or filebytes > length or fileoff > len(data) or filebytes > len(data) - fileoff:
                raise ValueError('Invalid segment geometry')
            if length:
                segments.append({'name': name.rstrip(b'\0').decode(), 'va': va, 'bytes': length, 'file_offset': fileoff, 'file_bytes': filebytes, 'protection': prot, 'maximum_protection': maxprot})
            for i in range(nsects):
                sectname, segname, address, n, pos = struct.unpack_from('<16s16sQQI', data, offset + 72 + i * 80)
                flags = struct.unpack_from('<I', data, offset + 72 + i * 80 + 64)[0]
                if address < va or address + n > va + length or (flags & 0xff not in (1, 0x0c, 0x12) and (pos > len(data) or n > len(data) - pos)):
                    raise ValueError('Section outside segment/file bounds')
                sections.append({'name': sectname.rstrip(b'\0').decode(), 'segment': segname.rstrip(b'\0').decode(), 'va': address, 'bytes': n, 'file_offset': pos, 'kind': flags & 0xff, 'protection': prot})
        elif command == 5:
            if entry is not None or size != 288 or struct.unpack_from('<II', data, offset + 8) != (6, 68):
                raise ValueError('Invalid or duplicate LC_UNIXTHREAD')
            entry = struct.unpack_from('<Q', data, offset + 272)[0]
        elif command == 2:
            if size != 24 or symtab is not None:
                raise ValueError('Bad symbol table')
            symtab = struct.unpack_from('<4I', data, offset + 8)
        offset += size
    if offset != end or entry is None or not segments:
        raise ValueError('Missing segments/entry or command consumption mismatch')
    for index, s in enumerate(segments):
        for t in segments[:index]:
            if s['va'] < t['va'] + t['bytes'] and t['va'] < s['va'] + s['bytes']:
                raise ValueError('Overlapping virtual segments')
    base = min(s['va'] for s in segments)
    top = max(s['va'] + s['bytes'] for s in segments)
    if base % 4096 or entry % 4 or top - base > WINDOW - 0x200000 or not any(s['va'] <= entry < s['va'] + s['file_bytes'] and s['protection'] & 4 for s in segments):
        raise ValueError('DarwinBoot cannot load this layout')
    code = [s for s in sections if s['name'] == '__text' and s['segment'] in ('__TEXT', '__TEXT_EXEC')][0]
    integrity = [s for s in sections if s['name'] == '__fips_hmacs']
    if len(integrity) != 1 or integrity[0]['bytes'] != 32 or code['file_offset'] + code['bytes'] > len(data):
        raise ValueError('Bad POST sections')
    macpos = integrity[0]['file_offset']
    if macpos > len(data) - 32 or code['file_offset'] <= macpos < code['file_offset'] + code['bytes'] or code['va'] - base != code['file_offset']:
        raise ValueError('POST runtime mapping mismatch')
    calculated = hmac.new(b'\0', data[code['file_offset']:code['file_offset'] + code['bytes']], 'sha256').digest()
    if not hmac.compare_digest(calculated, data[macpos:macpos + 32]):
        raise ValueError('Source crypto POST HMAC mismatch')
    if not symtab:
        raise ValueError('No native symbols')
    syoff, sycount, stroff, strbytes = symtab
    if syoff > len(data) or sycount > (len(data) - syoff) // 16 or stroff > len(data) or strbytes > len(data) - stroff:
        raise ValueError('Symbol table outside file')
    wanted = {'_arm_init', '_arm_vm_init', '_pmap_bootstrap', '_source_corecrypto14_bootstrap', '__ZN13ArmDTPlatform9configureEP9IOService'}
    if provenance:
        wanted |= USB_SYMBOLS | {'_source_pthread_bootstrap'}
        if provenance['control_protocol'] == 1:
            wanted |= set(CONTROL_SYMBOLS)
    symbols = {}
    dma = None
    for index in range(sycount):
        strindex, kind, sect, desc, value = struct.unpack_from('<IBBHQ', data, syoff + index * 16)
        if strindex >= strbytes:
            raise ValueError('Symbol string outside table')
        tail = data.find(b'\0', stroff + strindex, stroff + strbytes)
        if tail < 0:
            raise ValueError('Unterminated symbol')
        name = data[stroff + strindex:tail].decode('ascii', 'replace')
        if name in wanted and not kind & 0xe0 and kind & 0x0e == 0x0e and sect:
            if not any(s['va'] <= value < s['va'] + s['file_bytes'] and s['protection'] & 4 for s in segments):
                raise ValueError('Required symbol is not in executable bytes: ' + name)
            symbols[name] = {'va': hex(value), 'section': sect, 'kind': kind}
        if provenance and name == '_kernel_dma' and not kind & 0xe0 and kind & 0x0e == 0x0e and sect:
            if dma is not None or sect > len(sections):
                raise ValueError('Ambiguous or invalid permanent kernel USB DMA symbol')
            dma = {'va': value, 'section': sections[sect - 1]}
    if set(symbols) != wanted:
        raise ValueError('Missing true platform/kernel/crypto symbols: ' + str(wanted - set(symbols)))
    if provenance:
        crypto = provenance['crypto_evidence']
        if crypto.get('code_file_offset') != hex(code['file_offset']) or crypto.get('code_bytes') != code['bytes'] or crypto.get('hmac_file_offset') != hex(macpos) or crypto.get('hmac_sha256') != calculated.hex():
            raise ValueError('Recomputed POST HMAC does not match CI crypto evidence')
        if b'K70XNU001\0' not in data:
            raise ValueError('Expected kernel USB serial identity missing from actual Mach-O')
        if dma is None or dma['va'] % 0x4000 or dma['section']['kind'] != 1 or not dma['section']['protection'] & 2 or dma['va'] < dma['section']['va'] or dma['va'] + 0x4000 > dma['section']['va'] + dma['section']['bytes']:
            raise ValueError('Kernel USB DMA must be 16KiB aligned permanent writable BSS storage')
        for marker in (b'arm_vm_init returned; starting kernel-owned USB', b'PE_init_platform(FALSE) returned; XNU C is executing'):
            if marker not in data:
                raise ValueError('Actual kernel is missing the reviewed execution checkpoint string')
    serial_code_symbols = []
    for needle in (b'_serial_init\0', b'_serial_putc\0', b'_console_write\0'):
        if needle in data:
            serial_code_symbols.append(needle[:-1].decode())
    return {'status': 'pinned-CI-kernel-offline-contract-passed', 'kernel': str(path), 'bytes': len(data), 'sha256': digest, 'usb_debug_provenance': provenance,
            'usb_dma_image_offset': hex(dma['va'] - base) if dma else None, 'usb_dma_bytes': 0x4000 if dma else None,
            'loader': {'window_bytes': WINDOW, 'va_base': hex(base), 'va_end': hex(top), 'span_bytes': top - base, 'entry_va': hex(entry), 'entry_offset': hex(entry - base), 'physical_alignment': 0x200000, 'physical_low_bits': hex(base & 0x1fffff)},
            'post_hmac': {'matched': True, 'code_offset': hex(code['file_offset']), 'code_bytes': code['bytes'], 'hmac_offset': hex(macpos), 'calculated_sha256': calculated.hex(), 'runtime_selftests_executed': False},
            'required_symbols': symbols, 'generic_serial_symbols': serial_code_symbols, 'generic_serial_symbols_are_usb_support': False,
            'segments': segments, 'physical_dram_measured': False, 'hardware_boot_tested_by_this_check': False}


def map_candidates(report, inspected):
    rows = report['memory_map']
    runs = sorted((row['base'], row['base'] + row['pages'] * 4096) for row in rows if row['type'] == 7 and row['pages'])
    merged = []
    for base, end in runs:
        if merged and base < merged[-1][1]:
            raise ValueError('Overlapping free descriptors')
        if merged and base == merged[-1][1]:
            merged[-1][1] = end
        else:
            merged.append([base, end])
    alignment, low, size = 0x200000, int(inspected['loader']['physical_low_bits'], 0), inspected['loader']['window_bytes']
    candidates = []
    for base, end in merged:
        candidate = (base & -alignment) + low
        if candidate < base:
            candidate += alignment
        if candidate + size <= end:
            candidates.append({'free_run_base': hex(base), 'free_run_end': hex(end), 'candidate': hex(candidate), 'window_bytes': size, 'hardware_dram_validated': False})
    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--observed-map', required=True, type=Path)
    parser.add_argument('--kernel-manifest', type=Path, help='Adjacent exact USB debug CI manifest; old kernel pin remains the default')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = inspect(args.kernel, args.kernel_manifest)
    result['prior_observed_free_candidates'] = map_candidates(json.loads(args.observed_map.read_text()), result)
    result['candidate_limit'] = 'prior EFI allocation geometry only; current AllocatePages plus independent live DRAM/reservation containment still required'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
