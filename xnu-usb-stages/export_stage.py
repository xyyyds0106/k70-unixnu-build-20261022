"""Export a reviewable xnu-usb-stages/ tree; no Git, CI or device operations."""
import argparse
from pathlib import Path
import shutil
from bundle_contract import validate

ROOT = Path(__file__).resolve().parents[2]


def export(destination):
    bundle = ROOT/'sources/K70XnuUsbStages'
    validate(bundle, Path(__file__).parent)
    if destination.exists():
        raise ValueError('Refusing to overwrite an existing stage directory')
    destination.mkdir(parents=True)
    shutil.copytree(bundle, destination/'xnu-usb-stages/bundle')
    for name in ['prepare_ci.py', 'verify_kernel.py', 'base_verify_kernel.py', 'bundle_contract.py']:
        shutil.copyfile(Path(__file__).with_name(name), destination/'xnu-usb-stages'/name)
    # Installer checks all integration hashes as well as source hashes. Include
    # the other reviewed pure tools, but never execute/export a parent script.
    for name in validate(bundle)['integration_tools']:
        shutil.copyfile(Path(__file__).with_name(name), destination/'xnu-usb-stages'/name)
    from make_workflow import generate
    generate(destination/'.github/workflows/k70-usb-stages.yml')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    print(export(parser.parse_args().destination))
