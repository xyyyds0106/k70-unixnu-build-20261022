"""Create the independent USB-stage source bundle; frozen parents stay intact."""
import json
from pathlib import Path
from bundle_contract import (PATCH, PARENT_MANIFEST, PARENT_KERNEL, PARENT_CI_MANIFEST,
    INTEGRATION_TOOLS, sha, validate, source_generator, stage_contract)
ROOT = Path(__file__).resolve().parents[2]
PARENT = ROOT/'sources/K70XnuEarlyProbe'
BUNDLE = ROOT/'sources/K70XnuUsbStages'

def generate():
    raw = (PARENT/'source-manifest.json').read_bytes()
    if sha(raw) != PARENT_MANIFEST: raise ValueError('Frozen Early parent changed')
    parent = json.loads(raw)
    source = source_generator()
    sources = source.expected_sources(PARENT)
    artifact = ROOT/'out/ci/39912147245/k70-xnu-probes-platform-39912147245-1'
    if sha((artifact/'kernel.development.vermeer-build.macho').read_bytes()) != PARENT_KERNEL: raise ValueError('Actual parent kernel mismatch')
    ci_raw = (artifact/'usb-debug-manifest.json').read_bytes()
    if sha(ci_raw) != PARENT_CI_MANIFEST: raise ValueError('Actual parent CI manifest mismatch')
    payload = {name:(PARENT/name).read_bytes() for name in parent['files']}
    payload.update({'src/'+name:data for name,data in sources.items()})
    payload[PATCH] = source.build_patch(PARENT)
    payload.update({'stages-parent/'+name:(PARENT/name).read_bytes() for name in parent['files']})
    payload['stages-parent/source-manifest.json'] = raw
    payload['stages-parent-ci-manifest.json'] = ci_raw
    contract = stage_contract()
    payload['usb-stage-contract.json'] = (json.dumps(contract,indent=2)+'\n').encode()
    if BUNDLE.exists():
        stale = {p.relative_to(BUNDLE).as_posix() for p in BUNDLE.rglob('*') if p.is_file()}-set(payload)-{'source-manifest.json'}
        if stale: raise ValueError('Refusing unexpected existing bundle files: '+str(stale))
    for name,data in payload.items():
        p = BUNDLE/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
    manifest = {k:v for k,v in parent.items() if k not in ('files','scope','integration_tools')}
    manifest.update(files={name:sha(data) for name,data in sorted(payload.items())},
        scope='Frozen Early control kernel plus selected pre-controller USB initialization probes; original crypto/platform/storage policy unchanged',
        usb_stages=contract, integration_tools={name:sha(Path(__file__).with_name(name).read_bytes()) for name in INTEGRATION_TOOLS})
    (BUNDLE/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    validate(BUNDLE,Path(__file__).parent)
    print(json.dumps({'bundle':str(BUNDLE),'manifest_sha256':sha((BUNDLE/'source-manifest.json').read_bytes()),'patch_sha256':manifest['files'][PATCH],'files':len(payload),'parent_unchanged':sha((PARENT/'source-manifest.json').read_bytes())==PARENT_MANIFEST}))
if __name__=='__main__': generate()
