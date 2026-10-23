"""Emit a separate proposed manual workflow; existing workflows are read only."""
import argparse
from pathlib import Path
from bundle_contract import once
ROOT = Path(__file__).resolve().parents[2]

def generate(output):
    source = ROOT/'ci/repository/.github/workflows/k70-early-probes.yml'
    text = source.read_text()
    text = once(text,'name: K70 early checkpoint probes','name: K70 USB initialization stages')
    text = text.replace('k70-xnu-probes-', 'k70-xnu-usb-stages-').replace('/xnu-probes/','/xnu-usb-stages/')
    text = once(text,"kind='k70-xnu-early-probe-source-kernel'", "kind='k70-xnu-usb-stages-source-kernel'")
    text = once(text,"parent_source_manifest_sha256=validation['early_probe_parent_source_manifest_sha256'],",
        "usb_stage_version=validation['usb_stage_version'],usb_stage_symbols=validation['usb_stage_symbols_verified'],\n"
        "              parent_source_manifest_sha256=validation['usb_stage_parent_source_manifest_sha256'],")
    text = once(text,"parent_kernel_sha256=validation['early_probe_parent_kernel_sha256'],",
        "parent_kernel_sha256=validation['usb_stage_parent_kernel_sha256'],")
    text = once(text,"scope='parent control kernel plus explicitly selected early PSCI probes; no crypto bypass, OS image or phone operation')",
        "scope='frozen Early kernel plus selected pre-controller USB initialization probes; no crypto bypass, OS image or phone operation')")
    text = once(text,"          if validation.get('early_probe_version')!=1: raise SystemExit('Actual early probe verification missing')\n",
        "          if validation.get('early_probe_version')!=1: raise SystemExit('Actual early probe verification missing')\n"
        "          if validation.get('usb_stage_version')!=1: raise SystemExit('Actual USB initialization stage verification missing')\n")
    output.parent.mkdir(parents=True,exist_ok=True); output.write_text(text)
    return output
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    print(generate(parser.parse_args().output))
