"""Independent, hermetic parent-source and selected early-probe contract."""
import difflib
import hashlib
import json
from pathlib import Path

PARENT_MANIFEST = '370e4f6c3da12641549fc4cc2c01b5d79dc24728a4cd6b231de5888e06bf0fea'
PARENT_KERNEL = '535e31251cd73d27ca9dcd5ea3e5fbfa1291187f69fbcec5c3abab5dba9c970a'
PARENT_CI_MANIFEST = 'cc54b6e4da4ed7d6f48b5a394a700ca4896be221850e9c8e23fe94f09cec3b6f'
BASE_VERIFIER = '54736d87b3d30c9d1dd7e129760a3fe24951f5ec8c55edb949ca75cd9a958334'
PROBE_SYMBOLS = ['_k70_xnu_probe', '_k70_probe_psci', '_k70_probe_wait']
INTEGRATION_TOOLS = ['base_verify_kernel.py', 'build_bundle.py', 'bundle_contract.py',
    'export_stage.py', 'inspect_kernel.py', 'make_workflow.py', 'prepare_ci.py',
    'test_bundle.py', 'verify_kernel.py']
ADAPTER = 'src/k70_xnu_usb.c'
PATCH = 'zzzz-k70-usb-log.patch'
NEW_FILES = {'src/k70_probe_logic.inc', 'src/k70_xnu_probe.inc', 'probe-contract.json',
             'parent-source-manifest.json', 'parent-ci-manifest.json',
             'parent-files/'+ADAPTER, 'parent-files/'+PATCH}
sha = lambda data: hashlib.sha256(data).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unique frozen parent context drift: '+repr(old))
    return text.replace(old, new)


def derive_adapter(raw):
    text = raw.decode()
    text = once(text, '#include "k70_xnu_control.inc"',
                '#include "k70_xnu_control.inc"\n#include "k70_xnu_probe.inc"')
    text = once(text, '    if (debug_enabled) control_init(args);',
                '    if (debug_enabled) control_init(args);\n    k70_probe_init(args);')
    text = once(text, '        k70_xnu_checkpoint("PE_init_platform(FALSE) returned; XNU C is executing");\n    }\n}',
                '        k70_xnu_checkpoint("PE_init_platform(FALSE) returned; XNU C is executing");\n    }\n    k70_xnu_probe(1);\n}')
    text = once(text, 'void k70_xnu_after_vm(void)\n{\n',
                'void k70_xnu_after_vm(void)\n{\n    k70_xnu_probe(3);\n')
    return text.encode()


def derive_patch(parent_patch, src):
    prefix = parent_patch.decode().split('--- /dev/null\n', 1)[0]
    prefix = once(prefix, '@@ -523,3 +525,7 @@', '@@ -523,3 +525,9 @@')
    prefix = once(prefix, '+\textern void k70_xnu_after_vm(void);\n',
                  '+\textern void k70_xnu_after_vm(void);\n+\textern void k70_xnu_probe(unsigned);\n')
    prefix = once(prefix, '+\tk70_xnu_checkpoint("arm_vm_init enter");\n',
                  '+\tk70_xnu_checkpoint("arm_vm_init enter");\n+\tk70_xnu_probe(2);\n')
    for name, data in sorted(src.items()):
        prefix += ''.join(difflib.unified_diff([], data.decode().splitlines(True),
                         fromfile='/dev/null', tofile='b/pexpert/arm/'+name, n=1))
    return prefix.encode()


def validate(bundle, tools=None):
    manifest = json.loads((bundle/'source-manifest.json').read_text())
    parent_raw = (bundle/'parent-source-manifest.json').read_bytes()
    if sha(parent_raw) != PARENT_MANIFEST:
        raise ValueError('Frozen parent source-manifest identity mismatch')
    parent = json.loads(parent_raw)
    ci_raw = (bundle/'parent-ci-manifest.json').read_bytes()
    if sha(ci_raw) != PARENT_CI_MANIFEST:
        raise ValueError('Frozen parent CI manifest identity mismatch')
    ci = json.loads(ci_raw)
    if ci['kernel_sha256'] != PARENT_KERNEL or ci['usb_bundle_manifest'] != parent or ci['usb_bundle_manifest_sha256'] != PARENT_MANIFEST:
        raise ValueError('Parent CI/source/kernel chain mismatch')
    for key in ('schema_version', 'xnu_commit', 'unixnu_commit', 'device_commit', 'serial', 'device_fixes', 'control'):
        if manifest.get(key) != parent.get(key):
            raise ValueError('Inherited source/config/control policy changed: '+key)
    files = manifest.get('files')
    if not isinstance(files, dict) or set(files) != set(parent['files']) | NEW_FILES:
        raise ValueError('Unexpected early-probe source inventory')
    actual_files = {str(p.relative_to(bundle)).replace('\\','/') for p in bundle.rglob('*') if p.is_file()}
    if actual_files != set(files) | {'source-manifest.json'}:
        raise ValueError('Uninventoried file in early-probe source bundle')
    for relative, expected in files.items():
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts or sha((bundle/p).read_bytes()) != expected:
            raise ValueError('Probe bundle file hash mismatch: '+relative)
    for relative, expected in parent['files'].items():
        if relative not in (ADAPTER, PATCH) and files[relative] != expected:
            raise ValueError('Unrelated parent bytes changed: '+relative)
    for relative in (ADAPTER, PATCH):
        if files['parent-files/'+relative] != parent['files'][relative]:
            raise ValueError('Frozen parent derivation input mismatch')
    if (bundle/ADAPTER).read_bytes() != derive_adapter((bundle/'parent-files'/ADAPTER).read_bytes()):
        raise ValueError('Adapter differs from the four reviewed probe-only edits')
    sources = {p.name: p.read_bytes() for p in (bundle/'src').iterdir() if p.is_file()}
    if (bundle/PATCH).read_bytes() != derive_patch((bundle/'parent-files'/PATCH).read_bytes(), sources):
        raise ValueError('Patch differs from hermetic inherited-source regeneration')
    probe = manifest.get('early_probe')
    contract = json.loads((bundle/'probe-contract.json').read_text())
    if not isinstance(probe, dict) or probe != contract or type(probe.get('version')) is not int or probe['version'] != 1:
        raise ValueError('Early-probe contract mismatch')
    if probe.get('parent_source_manifest_sha256') != PARENT_MANIFEST or probe.get('parent_kernel_sha256') != PARENT_KERNEL:
        raise ValueError('Early-probe parent pin mismatch')
    if probe.get('symbols') != PROBE_SYMBOLS or probe.get('default_mode') != 0 or probe.get('delay_ms') != 4000:
        raise ValueError('Early-probe mode/symbol/timer contract mismatch')
    if probe.get('modes') != {'1':'after-PE_FALSE-and-existing-early-log', '2':'immediately-before-arm_vm_init',
                            '3':'after-VM-before-USB-initialize'}:
        raise ValueError('Early-probe checkpoint definition mismatch')
    if probe.get('usb_or_efi_dependency') is not False or probe.get('pmic_or_storage_access') is not False:
        raise ValueError('Unexpected early-probe external hardware dependency')
    if set(manifest.get('integration_tools', {})) != set(INTEGRATION_TOOLS):
        raise ValueError('Unexpected integration-tool inventory')
    if tools is not None:
        for name, expected in manifest['integration_tools'].items():
            p = Path(name)
            if p.name != name or sha((tools/p).read_bytes()) != expected:
                raise ValueError('Early-probe integration tool drift: '+name)
        if sha((tools/'base_verify_kernel.py').read_bytes()) != BASE_VERIFIER:
            raise ValueError('Parent executable/HMAC verifier drift')
    return manifest
