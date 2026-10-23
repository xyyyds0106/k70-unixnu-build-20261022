"""Derive the new source bundle without writing the frozen parent or workflow."""
import hashlib
import json
from pathlib import Path
import shutil
from bundle_contract import (ADAPTER, PATCH, PARENT_MANIFEST, PARENT_KERNEL,
                             PARENT_CI_MANIFEST, PROBE_SYMBOLS, derive_adapter,
                             derive_patch, sha, validate, INTEGRATION_TOOLS)

ROOT = Path(__file__).resolve().parents[2]
PARENT = ROOT/'sources/K70XnuDebug'
BUNDLE = ROOT/'sources/K70XnuEarlyProbe'


def generate():
    raw = (PARENT/'source-manifest.json').read_bytes()
    if sha(raw) != PARENT_MANIFEST:
        raise ValueError('Refusing to derive from a changed historical parent')
    parent = json.loads(raw)
    for relative, expected in parent['files'].items():
        if sha((PARENT/relative).read_bytes()) != expected:
            raise ValueError('Frozen parent inventory drift: '+relative)
    artifact = ROOT/'out/ci/39906691508/k70-usb-debug-platform-39906691508-1'
    if sha((artifact/'kernel.development.vermeer-build.macho').read_bytes()) != PARENT_KERNEL:
        raise ValueError('Parent actual kernel identity mismatch')
    ci_raw = (artifact/'usb-debug-manifest.json').read_bytes()
    if sha(ci_raw) != PARENT_CI_MANIFEST:
        raise ValueError('Parent CI identity mismatch')
    for relative in parent['files']:
        if relative == PATCH:
            continue
        target = BUNDLE/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(derive_adapter((PARENT/relative).read_bytes()) if relative == ADAPTER else (PARENT/relative).read_bytes())
    (BUNDLE/'parent-source-manifest.json').write_bytes(raw)
    (BUNDLE/'parent-ci-manifest.json').write_bytes(ci_raw)
    for relative in (ADAPTER, PATCH):
        target = BUNDLE/'parent-files'/relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((PARENT/relative).read_bytes())
    contract = dict(version=1, parent_source_manifest_sha256=PARENT_MANIFEST,
        parent_kernel_sha256=PARENT_KERNEL, parent_ci_manifest_sha256=PARENT_CI_MANIFEST,
        bootarg='k70_probe', default_mode=0, modes={'1':'after-PE_FALSE-and-existing-early-log',
        '2':'immediately-before-arm_vm_init', '3':'after-VM-before-USB-initialize'},
        delay_ms=4000, counter='CNTPCT_EL0/CNTFRQ_EL0, 1MHz..1GHz, stable frequency, monotonic, stopped-clock and total-read budgets',
        failure='append RAM status and continue parent normal flow; no reset fallback',
        psci='actual ADT /psci exact compatible/method; VERSION>=1.0; FEATURES(SYSTEM_RESET)>=0; independent SMCCC32',
        symbols=PROBE_SYMBOLS, usb_or_efi_dependency=False, pmic_or_storage_access=False,
        crypto_post_hmac_and_platform_policy='inherited unchanged',
        evidence_limit='Host PLAN is input intent only; reset/recovery supports an inferred checkpoint, not received XNU log or full boot')
    (BUNDLE/'probe-contract.json').write_text(json.dumps(contract, indent=2)+'\n')
    src = {p.name:p.read_bytes() for p in (BUNDLE/'src').iterdir() if p.is_file()}
    (BUNDLE/PATCH).write_bytes(derive_patch((PARENT/PATCH).read_bytes(), src))
    manifest = {k:v for k,v in parent.items() if k not in ('files','scope')}
    payload = [p for p in BUNDLE.rglob('*') if p.is_file() and p.name != 'source-manifest.json']
    manifest['files'] = {str(p.relative_to(BUNDLE)).replace('\\','/'):sha(p.read_bytes()) for p in sorted(payload)}
    manifest['scope'] = 'Parent control kernel plus explicitly selected early PSCI checkpoint probes; no crypto/platform/storage change'
    manifest['early_probe'] = contract
    manifest['integration_tools'] = {name:sha(Path(__file__).with_name(name).read_bytes()) for name in INTEGRATION_TOOLS}
    (BUNDLE/'source-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    validate(BUNDLE, Path(__file__).parent)
    assert sha((PARENT/'source-manifest.json').read_bytes()) == PARENT_MANIFEST
    print(json.dumps({'bundle':str(BUNDLE), 'manifest_sha256':sha((BUNDLE/'source-manifest.json').read_bytes()),
                      'patch_sha256':manifest['files'][PATCH], 'files':len(manifest['files']),
                      'parent_unchanged':True}))


if __name__ == '__main__':
    generate()
