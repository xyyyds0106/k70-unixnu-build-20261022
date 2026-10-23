"""Emit a separate proposed manual CI workflow; never edits the old workflow."""
import argparse
from pathlib import Path
from bundle_contract import once

ROOT = Path(__file__).resolve().parents[2]


def generate(output):
    source = ROOT/'ci/repository/.github/workflows/k70-usb-debug.yml'
    text = source.read_text()
    text = once(text, 'name: K70 USB debug kernel', 'name: K70 early checkpoint probes')
    text = text.replace('group: k70-usb-debug-', 'group: k70-xnu-probes-')
    text = text.replace('/xnu-debug/', '/xnu-probes/')
    text = once(text, "scope='source platform kernel plus bounded diagnostic/reset USB control; no crypto bypass, OS image or phone operation')",
        "early_probe_version=validation['early_probe_version'],early_probe_symbols=validation['early_probe_symbols_verified'],\n"
        "              parent_source_manifest_sha256=validation['early_probe_parent_source_manifest_sha256'],\n"
        "              parent_kernel_sha256=validation['early_probe_parent_kernel_sha256'],\n"
        "              scope='parent control kernel plus explicitly selected early PSCI probes; no crypto bypass, OS image or phone operation')")
    text = once(text, "kind='k70-usb-debug-source-kernel'", "kind='k70-xnu-early-probe-source-kernel'")
    text = once(text, "          validation=verifier.verify(kernel,out/'crypto-hmac.json')\n",
        "          validation=verifier.verify(kernel,out/'crypto-hmac.json')\n"
        "          if validation.get('early_probe_version')!=1: raise SystemExit('Actual early probe verification missing')\n")
    text = text.replace('name: k70-usb-debug-', 'name: k70-xnu-probes-')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(generate(parser.parse_args().output))
