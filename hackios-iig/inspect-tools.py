"""Read installed Xcode IIG options; output only diagnostics, never tool binaries."""
import hashlib
import json
from pathlib import Path
import subprocess

out = Path('iig-out/tool-options')
out.mkdir(parents=True, exist_ok=True)
records = []
for tool in sorted(Path('/Applications').glob('Xcode*.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/iig')):
    label = tool.parents[6].stem
    record = dict(tool=str(tool), binary_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(), commands=[])
    for flag in ('--help', '-help', '--version'):
        command = [str(tool), flag]
        try:
            done = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=15)
            text = done.stdout + done.stderr
            code = done.returncode
        except subprocess.TimeoutExpired:
            text, code = 'Tool option query timed out', None
        file = label + flag.replace('-', '_') + '.txt'
        (out / file).write_text(text)
        record['commands'].append(dict(argv=command, returncode=code, output=file))
        print(json.dumps(dict(tool=str(tool), flag=flag, returncode=code, output=file)), flush=True)
    records.append(record)
(out / 'inventory.json').write_text(json.dumps(records, indent=2) + '\n')
