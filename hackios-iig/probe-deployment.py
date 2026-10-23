"""Probe the real IIG's documented deployment target option on one public file."""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path('xnu').resolve()
out = Path('iig-out/deployment-probes').resolve()
out.mkdir(parents=True, exist_ok=True)
manifest = json.loads(Path(__file__).with_name('input-manifest.json').read_text())
commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
assert commit == manifest['source_commit']
source = root / 'iokit/DriverKit/OSObject.iig'
assert hashlib.sha256(source.read_bytes()).hexdigest() == next(
    f['sha256'] for f in manifest['files'] if f['path'].endswith('/OSObject.iig'))
sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], text=True).strip()
tool = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--find', 'iig'], text=True).strip()
flags = [f'-I{root / p}' for p in ('iokit', 'osfmk', 'bsd', 'EXTERNAL_HEADERS')]
flags += ['-isysroot', sdk, '-x', 'c++', '-std=gnu++1z']
flags += ['-D' + d for d in manifest['defines']]
records = []
for deployment in ('16.5', '22.0', '22.5', 'ios16.5', 'iOS16.5'):
    folder = out / deployment
    folder.mkdir()
    header, impl = folder / 'OSObject.h', folder / 'OSObject.iig.cpp'
    cmd = [tool, '--def', str(source), '--header', str(header), '--impl', str(impl),
           '--framework-name', 'DriverKit', '--deployment-target', deployment, '--', *flags]
    done = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=30)
    (folder / 'tool.log').write_text(done.stdout + done.stderr)
    record = dict(deployment=deployment, argv=cmd, returncode=done.returncode, files=[])
    for file in (header, impl):
        if file.is_file():
            data = file.read_bytes()
            record['files'].append(dict(path=str(file.relative_to(out)), bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(), kernelContent_occurrences=data.count(b'kernelContent')))
    records.append(record)
    print(json.dumps(record), flush=True)
(out / 'probe-report.json').write_text(json.dumps(dict(
    kind='generator-option-probe-not-kernel-qualification', source_commit=commit, probes=records), indent=2) + '\n')
