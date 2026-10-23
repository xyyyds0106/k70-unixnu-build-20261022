"""Host-only tests of generated production source; never accesses a device.

The AArch64 object uses API declaration stubs and proves real architectural
instructions/symbols, not the complete XNU ABI. macOS CI does the real link.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PARENT = ROOT / 'sources/K70XnuEarlyProbe'
SCRATCH = ROOT / '.tmp/xnu-usb-stages-source-tests'
spec = importlib.util.spec_from_file_location('usb_stage_source_contract', HERE / 'source-contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def body(text, name):
    match = re.search(r'(?m)^(?:static|STATIC)[^\n]*\b' + re.escape(name) + r'\s*\([^;]*?\)\s*\n\{', text)
    if not match:
        raise ValueError('No unique actual function definition: ' + name)
    start = text.index('{', match.start())
    depth = 1
    end = start + 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[match.start():end] + '\n'


def run(argv, **kw):
    subprocess.run([str(x) for x in argv], check=True, **kw)


def patch_test(src, patch):
    # These are the exact checked-in upstream files plus the known earlier
    # boot-progress patch contexts, matching the frozen parent's own test.
    # Full preparation against all earlier patches is checked by macOS CI.
    with tempfile.TemporaryDirectory(prefix='patch-', dir=SCRATCH) as tmp:
        tree = Path(tmp)
        reference = ROOT / 'sources/K70XnuDebug/reference'
        for name in ('osfmk/arm/arm_init.c', 'pexpert/arm/pe_serial.c', 'pexpert/arm/pe_kprintf.c', 'osfmk/console/serial_console.c'):
            text = (reference / name).read_text()
            if name.endswith('arm_init.c'):
                text = text.replace('\tPE_init_platform(FALSE, args); /* Get platform expert set up */', '\tPE_init_platform(FALSE, args); /* Get platform expert set up */\n\tboot_progress_init();')
                text = text.replace('\tarm_vm_init(xmaxmem, args);', '\tboot_progress_stage("arm_vm_init enter");\n\tarm_vm_init(xmaxmem, args);\n\tboot_progress_stage("arm_vm_init returned");')
            if name.endswith('pe_kprintf.c'):
                text = text.replace('PE_init_kprintf(void)\n{', 'PE_init_kprintf(void)\n{\n\tif (boot_progress_active()) { PE_kputc = boot_progress_putc; return; }')
            if name.endswith('serial_console.c'):
                text = text.replace('_cnputc(char c, bool poll)\n{', '_cnputc(char c, bool poll)\n{\n\tif (boot_progress_active()) { boot_progress_putc(c); return; }')
            target = tree / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text)
        startup = tree / 'osfmk/kern/startup.c'; startup.parent.mkdir(parents=True, exist_ok=True)
        startup.write_text((reference / 'osfmk/kern-startup.c').read_text().replace('\tclock_service_create();', '\tclock_service_create();\n\tboot_progress_start();'))
        path = SCRATCH / 'actual.patch'; path.write_bytes(patch)
        run(['git', '-C', tree, 'apply', '--check', path]); run(['git', '-C', tree, 'apply', path])
        for name, raw in src.items(): assert (tree / 'pexpert/arm' / name).read_bytes() == raw
        run(['git', '-C', tree, 'apply', '--reverse', '--check', path]); run(['git', '-C', tree, 'apply', '--reverse', path]); run(['git', '-C', tree, 'apply', '--check', path])
    print('PASS real git apply/check/reverse/reapply against the frozen upstream context fixture; every generated source byte matches', flush=True)


def main():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    os.environ['TMPDIR'] = str(SCRATCH)
    src = contract.expected_sources(PARENT)
    directory = SCRATCH / 'src'; directory.mkdir(exist_ok=True)
    for name, raw in src.items(): (directory / name).write_bytes(raw)
    adapter, transport = src['k70_xnu_usb.c'].decode(), src['k70_usb_transport.inc'].decode()
    state = transport[:transport.index('STATIC CONST UINTN mTrbOffset')]
    state += transport[transport.index('typedef enum {'):transport.index('} m;') + len('} m;')] + '\n'
    (directory / 'actual-state.inc').write_text(state)
    functions = '\n'.join(body(adapter, name) for name in ('MapKernelDevices', 'AllocateDma'))
    functions += '\n'.join(body(transport, name) for name in ('StopEngine', 'Fail', 'CheckSmmu', 'K70UsbCdcInitialize'))
    ctr = '__asm__ __volatile__ ("mrs %0, ctr_el0" : "=r" (Ctr));'
    assert functions.count(ctr) == 1
    functions = functions.replace(ctr, 'Ctr = (UINT64)(fault == CACHE_BAD ? 5U : 4U) << 16; /* Mock privileged CTR only. */')
    (directory / 'actual-functions.inc').write_text(functions)
    old = (PARENT / 'src/k70_xnu_probe.inc').read_text()
    marker = '    k70_probe_attempted = true;'
    new_core = body(src['k70_xnu_probe.inc'].decode(), 'k70_probe_reset_core')
    assert old[old.index(marker):].strip() == new_core[new_core.index(marker):].strip()
    assert src['k70_probe_logic.inc'] == (PARENT / 'src/k70_probe_logic.inc').read_bytes()
    print('PASS original PSCI/counter/reset body and clock logic preserved byte-for-byte; wrappers alone select new checkpoints', flush=True)
    for name in ('parser', 'gates'):
        out = SCRATCH / ('test-' + name)
        run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I' + str(directory), HERE / ('source-test-' + name + '.c'), '-o', out])
        run([out])
    patch_test(src, contract.build_patch(PARENT))
    include = SCRATCH / 'include'
    run(['python3', '-B', ROOT / 'tools/xnu-debug/write-syntax-stubs.py', include])
    obj = SCRATCH / 'k70_xnu_usb.o'
    run(['clang', '--target=aarch64-none-elf', '-std=gnu11', '-O2', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-I' + str(include), '-I' + str(directory), '-c', directory / 'k70_xnu_usb.c', '-o', obj])
    dis = subprocess.check_output(['llvm-objdump', '-dr', str(obj)], text=True)
    syms = subprocess.check_output(['llvm-nm', str(obj)], text=True)
    for name in (*contract.STAGE_SYMBOLS, '_k70_xnu_probe', '_k70_probe_wait', '_k70_probe_psci'):
        assert re.search(r'\b' + re.escape(name.lstrip('_')) + r'$', syms, re.M), name
    assert re.search(r'\bsmc\s+#?0', dis) and re.search(r'\bhvc\s+#?0', dis)
    assert 'CNTPCT_EL0' in dis and 'CNTFRQ_EL0' in dis
    reloc = re.findall(r'R_AARCH64_CALL26\s+k70_xnu_usb_stage\s*$', dis, re.M)
    assert len(reloc) == 3, 'Actual Initialize needs exactly three stage BL relocations'
    (SCRATCH / 'disassembly.txt').write_text(dis)
    report = dict(status='host-source-and-AArch64-instruction-tests-passed', parent_manifest_sha256=contract.PARENT_MANIFEST,
        source_hashes={k:contract.sha(v) for k,v in src.items()}, patch_sha256=contract.sha(contract.build_patch(PARENT)),
        object_sha256=contract.sha(obj.read_bytes()), actual_reset_core_body_unchanged=True, api_stubs_do_not_prove_full_XNU_ABI=True,
        device_operations=False, real_kernel_link_executed=False)
    (SCRATCH / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS actual production AArch64 object: real SMC/HVC/CNTPCT/CNTFRQ, retained noinline symbols and exactly three stage calls; real XNU link remains CI responsibility', flush=True)


if __name__ == '__main__':
    main()
