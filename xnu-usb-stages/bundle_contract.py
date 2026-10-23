"""Hermetic USB initialization stages, chained to the frozen Early kernel."""
import hashlib
import importlib.util
import json
from pathlib import Path

PARENT_MANIFEST = 'd3306df76cd9d4571502199594b204b58528b7f6b187f89ced7cdee792bdc246'
PARENT_KERNEL = '27b71a74f5d14c729f2c2799bf8a2a9c90819c0ac544f7b28026af6a4c4ebfee'
PARENT_CI_MANIFEST = '8f6813d1d144b1b8436ac2ac52cf24f3a0413d6762448345b836685e8b586bae'
BASE_VERIFIER = '54736d87b3d30c9d1dd7e129760a3fe24951f5ec8c55edb949ca75cd9a958334'
EARLY_PARENT_MANIFEST = '370e4f6c3da12641549fc4cc2c01b5d79dc24728a4cd6b231de5888e06bf0fea'
EARLY_PARENT_KERNEL = '535e31251cd73d27ca9dcd5ea3e5fbfa1291187f69fbcec5c3abab5dba9c970a'
PROBE_SYMBOLS = ['_k70_xnu_probe', '_k70_probe_psci', '_k70_probe_wait']
STAGE_SYMBOLS = ['_k70_xnu_usb_stage', '_k70_xnu_usb_stage_reset', '_k70_probe_reset_core']
BOUNDARY_SYMBOLS = ['_MapKernelDevices', '_CheckSmmu', '_AllocateDma', '_StopEngine', '_K70UsbCdcInitialize']
KIND = 'k70-xnu-usb-stages-source-kernel'
INTEGRATION_TOOLS = ['base_verify_kernel.py', 'build_bundle.py', 'bundle_contract.py',
    'export_stage.py', 'inspect_kernel.py', 'make_workflow.py', 'prepare_ci.py',
    'test_bundle.py', 'verify_kernel.py', 'source-contract.py', 'source-tests.py', 'source-syntax.sh',
    'source-test-parser.c', 'source-test-gates.c']
PATCH = 'zzzz-k70-usb-log.patch'
sha = lambda raw: hashlib.sha256(raw).hexdigest()

def once(text, old, new):
    if text.count(old) != 1: raise ValueError('Unique qualified context drift: '+repr(old))
    return text.replace(old, new)

def source_generator(tools=None):
    path = (tools or Path(__file__).parent)/'source-contract.py'
    spec = importlib.util.spec_from_file_location('k70_usb_stage_source_generator', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    if module.PARENT_MANIFEST != PARENT_MANIFEST or module.STAGE_SYMBOLS != STAGE_SYMBOLS:
        raise ValueError('Source generator identity contract mismatch')
    return module

def stage_contract():
    return dict(version=1, kind=KIND, parent_source_manifest_sha256=PARENT_MANIFEST,
        parent_kernel_sha256=PARENT_KERNEL, parent_ci_manifest_sha256=PARENT_CI_MANIFEST,
        bootarg='k70_usb_stage', required_flags={'k70_probe':'3','k70_usb':'1'},
        default='absent preserves frozen Early behavior',
        modes={'1':'four ml_io_map succeeded; before first device MMIO read',
               '2':'all hardware guards and halted checks succeeded; before AllocateDma',
               '3':'owned BSS DMA translation/linear/cache guards succeeded; before ControllerTouched and controller writes'},
        invalid='any present invalid/conflicting stage suppresses all legacy early probes and aborts initialization at U1',
        selected='selected reset return/failure aborts initialization; no fallthrough into controller writes',
        delay_ms=4000, symbols=STAGE_SYMBOLS, boundary_symbols=BOUNDARY_SYMBOLS,
        reset='shared bounded independent ADT PSCI core; parent counter/frequency/iteration gates unchanged',
        controller_writes_before_selected_stage=False, dma_started_before_selected_stage=False,
        crypto_post_hmac_and_platform_policy='inherited unchanged',
        evidence_limit='Host PLAN is intent only; automatic return permits inferred checkpoint, not received XNU log or full boot')

def validate(bundle, tools=None):
    bundle = Path(bundle)
    manifest = json.loads((bundle/'source-manifest.json').read_text())
    parent_dir = bundle/'stages-parent'
    parent_raw = (parent_dir/'source-manifest.json').read_bytes()
    if sha(parent_raw) != PARENT_MANIFEST: raise ValueError('Frozen Early parent source identity mismatch')
    parent = json.loads(parent_raw)
    ci_raw = (bundle/'stages-parent-ci-manifest.json').read_bytes()
    if sha(ci_raw) != PARENT_CI_MANIFEST: raise ValueError('Frozen Early parent CI identity mismatch')
    ci = json.loads(ci_raw)
    if ci.get('kernel_sha256') != PARENT_KERNEL or ci.get('usb_bundle_manifest') != parent or ci.get('usb_bundle_manifest_sha256') != PARENT_MANIFEST:
        raise ValueError('Frozen Early source/CI/kernel chain mismatch')
    for key in ('schema_version','xnu_commit','unixnu_commit','device_commit','serial','device_fixes','control','early_probe'):
        if manifest.get(key) != parent.get(key): raise ValueError('Inherited policy changed: '+key)
    source = source_generator(tools)
    expected_src = source.expected_sources(parent_dir)
    expected = {name:(parent_dir/name).read_bytes() for name in parent['files']}
    expected.update({'src/'+name:raw for name,raw in expected_src.items()})
    expected[PATCH] = source.build_patch(parent_dir)
    expected.update({'stages-parent/'+name:(parent_dir/name).read_bytes() for name in parent['files']})
    expected['stages-parent/source-manifest.json'] = parent_raw
    expected['stages-parent-ci-manifest.json'] = ci_raw
    expected['usb-stage-contract.json'] = (bundle/'usb-stage-contract.json').read_bytes()
    files = manifest.get('files')
    if not isinstance(files,dict) or set(files) != set(expected): raise ValueError('Unexpected USB stage inventory')
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    if actual != set(expected)|{'source-manifest.json'}: raise ValueError('Uninventoried USB stage file')
    for name,raw in expected.items():
        if sha(raw) != files[name] or (bundle/name).read_bytes() != raw:
            raise ValueError('Non-hermetic USB stage source/patch: '+name)
    contract = json.loads((bundle/'usb-stage-contract.json').read_text())
    if type(contract.get('version')) is not int or contract != stage_contract() or manifest.get('usb_stages') != contract:
        raise ValueError('USB stage selection/safety contract mismatch')
    if set(manifest.get('integration_tools',{})) != set(INTEGRATION_TOOLS): raise ValueError('Unexpected integration-tool inventory')
    if tools is not None:
        for name,digest in manifest['integration_tools'].items():
            if sha((tools/name).read_bytes()) != digest: raise ValueError('Integration tool drift: '+name)
        if sha((tools/'base_verify_kernel.py').read_bytes()) != BASE_VERIFIER: raise ValueError('POST/HMAC verifier drift')
    return manifest
