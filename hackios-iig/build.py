#!/usr/bin/env python3
"""Generate XNU 8796 DriverKit glue with the real Xcode iig, without building XNU."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def run(args):
    print('+ ' + ' '.join(map(str, args)), flush=True)
    return subprocess.check_output(list(map(str, args)), text=True, stderr=subprocess.STDOUT)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True, type=pathlib.Path)
    p.add_argument('--out', required=True, type=pathlib.Path)
    p.add_argument('--sdk', default='iphoneos')
    p.add_argument('--sysroot', type=pathlib.Path)
    a = p.parse_args()
    root = a.source.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(pathlib.Path(__file__).with_name('input-manifest.json').read_text())
    commit = run(['git', '-C', root, 'rev-parse', 'HEAD']).strip()
    if commit != manifest['source_commit']:
        raise SystemExit('XNU source commit mismatch: ' + commit)
    sdk = str(a.sysroot.resolve()) if a.sysroot else run(['xcrun', '--sdk', a.sdk, '--show-sdk-path']).strip()
    iig = run(['xcrun', '--sdk', a.sdk, '--find', 'iig']).strip()
    # The Apple source make rule uses these source include roots; SDK headers
    # resolve standard integer, Mach and system types. No SDK files are uploaded.
    flags = [f'-I{root / sub}' for sub in ('iokit', 'osfmk', 'bsd', 'EXTERNAL_HEADERS')]
    flags += ['-isysroot', sdk, '-x', 'c++', '-std=gnu++1z']
    flags += ['-D' + d for d in manifest['defines']]
    evidence = {'source_commit': commit, 'sdk_path': sdk, 'sdk_name': a.sdk,
                'sdk_version': run(['xcrun', '--sdk', a.sdk, '--show-sdk-version']).strip(),
                'iig_path': iig, 'files': [], 'commands': [], 'status': 'running'}
    (out / 'input-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for item in manifest['files']:
        src = root / item['path']
        actual = hashlib.sha256(src.read_bytes()).hexdigest()
        if actual != item['sha256']:
            raise SystemExit('Public .iig source hash mismatch: ' + item['path'])
        header = out / (src.stem + '.h')
        impl = out / (src.stem + '.iig.cpp')
        cmd = [iig, '--def', src, '--header', header, '--impl', impl,
               '--framework-name', 'DriverKit', '--', *flags]
        evidence['commands'].append(list(map(str, cmd)))
        try:
            log = run(cmd)
        except subprocess.CalledProcessError as e:
            (out / (src.stem + '.log')).write_text(e.output or '')
            evidence['status'] = 'failed'
            evidence['failure'] = {'file': item['path'], 'returncode': e.returncode}
            (out / 'generation-report.json').write_text(json.dumps(evidence, indent=2) + '\n')
            print(e.output, file=sys.stderr)
            return e.returncode
        (out / (src.stem + '.log')).write_text(log)
        for artifact in (header, impl):
            data = artifact.read_bytes()
            evidence['files'].append({'path': artifact.name, 'bytes': len(data),
                                      'sha256': hashlib.sha256(data).hexdigest()})
    evidence['status'] = 'passed'
    (out / 'generation-report.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
