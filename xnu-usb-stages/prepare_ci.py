#!/usr/bin/env python3
"""Install the reviewed USB patch into a fresh, pinned device build recipe.

The upstream source checkout stays unchanged. Its actual preparer copies
patches to a device-local writable directory; this hook adds one final patch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from bundle_contract import validate

DEVICE = 'd4dbb3683023a17bb468b9774f52c87f3060e739'
ORIGINAL_PREPARER_SHA = 'cddb4858c243ef317cc6c6f141c775e8615b6808b85dce6c487389976a2798ac'
HOOK = '''    # K70 kernel USB patch: the upstream source/crypto recipes remain intact.
    usb_bundle = Path(__file__).resolve().parent / "k70-xnu-usb-stages"
    usb_manifest = __import__("json").loads((usb_bundle / "source-manifest.json").read_text())
    for relative, expected in usb_manifest["files"].items():
        data = (usb_bundle / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("K70 USB source hash mismatch: " + relative)
    shutil.copy2(usb_bundle / "zzzz-k70-usb-log.patch", local / "zzzz-k70-usb-log.patch")
    # Bootstrap and final XNU passes apply the same patch set. Remove the new
    # dependent patch before upstream removes its existing zzz hooks. This is
    # only the build-tree script copy; the checked upstream source stays clean.
    build_script = tree / "scripts/build-xnu-4k-baseline.sh"
    upstream_script = upstream / "scripts/build-xnu-4k-baseline.sh"
    script_data = build_script.read_bytes()
    if build_script.is_symlink() or script_data != upstream_script.read_bytes():
        raise ValueError("Expected the unmodified build-tree script copy")
    script_text = script_data.decode()
    late_anchor = 'for LATE_PATCH in "$ROOT/patches/xnu/zzz-boot-progress.patch"'
    if script_text.count(late_anchor) != 1:
        raise ValueError("Unexpected upstream late-patch reverse loop")
    build_script.write_bytes(script_text.replace(late_anchor,
        'for LATE_PATCH in "$ROOT/patches/xnu/zzzz-k70-usb-log.patch" "$ROOT/patches/xnu/zzz-boot-progress.patch"').encode())
    (tree / ".cache/k70-usb-build-script.json").write_text(__import__("json").dumps({
        "sha256_before": hashlib.sha256(script_data).hexdigest(),
        "sha256_after": hashlib.sha256(build_script.read_bytes()).hexdigest(),
        "change": "reverse new dependent USB patch before existing late patches"
    }, indent=2) + "\\n")
'''


def install(device, bundle):
    validate(bundle, Path(__file__).resolve().parent)
    actual = subprocess.check_output(['git', '-C', str(device), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != DEVICE:
        raise ValueError('Use the pinned source-build device checkout: ' + DEVICE)
    manifest = json.loads((bundle / 'source-manifest.json').read_text())
    if manifest['xnu_commit'] != 'd8b80295118ef25ac3a784134bcf95cd8e88109f':
        raise ValueError('Unexpected kernel source pin')
    for relative, expected in manifest['files'].items():
        if hashlib.sha256((bundle / relative).read_bytes()).hexdigest() != expected:
            raise ValueError('Bundle hash mismatch: ' + relative)
    preparer = device / 'tools/prepare_kernel_patches.py'
    data = preparer.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != ORIGINAL_PREPARER_SHA:
        raise ValueError('Expected original pinned preparer: ' + digest)
    text = data.decode()
    anchor = '    (local / PATCH).write_bytes(patched)\n'
    if text.count(anchor) != 1:
        raise ValueError('Unexpected patch-preparer insertion point')
    destination = device / 'tools/k70-xnu-usb-stages'
    if destination.exists():
        raise ValueError('Refusing to overwrite an existing debug bundle')
    fixes = manifest.get('device_fixes')
    if fixes is None or fixes.get('setting') != 'CONFIG_XNU_DT_PANIC_REGION=y':
        raise ValueError('Required DT panic-region configuration fix is missing')
    for relative, change in fixes['files'].items():
        if hashlib.sha256((device/relative).read_bytes()).hexdigest() != change['before_sha256']:
            raise ValueError('Pinned device fix source mismatch: '+relative)
        if hashlib.sha256((bundle/'device-files'/relative).read_bytes()).hexdigest() != change['after_sha256']:
            raise ValueError('Pinned device fix payload mismatch: '+relative)
    shutil.copytree(bundle, destination, ignore=shutil.ignore_patterns('reference', '__pycache__'))
    preparer.write_text(text.replace(anchor, anchor + HOOK))
    for relative in fixes['files']:
        shutil.copyfile(bundle/'device-files'/relative,device/relative)
    report = {'schema_version': 1, 'device_commit': actual,
              'preparer_sha256_before': digest,
              'preparer_sha256_after': hashlib.sha256(preparer.read_bytes()).hexdigest(),
              'bundle_manifest': manifest,
              'device_file_fixes': fixes,
              'crypto_policy': 'unchanged source corecrypto POST and final HMAC sealing'}
    (destination / 'installation.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(install(args.device.resolve(), args.bundle.resolve()), indent=2))


if __name__ == '__main__':
    main()
