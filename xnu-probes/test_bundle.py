"""No hardware: source lineage, real patch/installer, old-kernel rejection."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bundle_contract import validate, PARENT_MANIFEST, PARENT_KERNEL, sha

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT/'sources/K70XnuEarlyProbe'
PARENT = ROOT/'sources/K70XnuDebug'
OUT = ROOT/'build/xnu-early-probe-tests'


def module(name):
    spec = importlib.util.spec_from_file_location('probe_'+name, Path(__file__).with_name(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class BundleTests(unittest.TestCase):
    def temp(self):
        return tempfile.TemporaryDirectory(dir=OUT)

    def mutation_rejected(self, mutate):
        with self.temp() as temporary:
            bundle = Path(temporary)/'bundle'
            shutil.copytree(BUNDLE,bundle)
            manifest = json.loads((bundle/'source-manifest.json').read_text())
            mutate(bundle, manifest)
            # Even an adversary updating all affected bundle file hashes does
            # not override pinned parent lineage or the exact derivation.
            for name in manifest['files']:
                if (bundle/name).exists(): manifest['files'][name]=sha((bundle/name).read_bytes())
            (bundle/'source-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): validate(bundle)

    def test_manifest_and_frozen_parent(self):
        manifest = validate(BUNDLE,Path(__file__).parent)
        self.assertEqual(sha((PARENT/'source-manifest.json').read_bytes()),PARENT_MANIFEST)
        self.assertEqual(len(manifest['files']),19)
        self.assertEqual(manifest['early_probe']['parent_kernel_sha256'],PARENT_KERNEL)

    def test_parent_manifest_tamper(self):
        self.mutation_rejected(lambda b,m:(b/'parent-source-manifest.json').write_bytes(b'{}'))

    def test_unrelated_source_tamper_rehashed(self):
        self.mutation_rejected(lambda b,m:(b/'src/k70_usb_transport.inc').write_bytes(b'changed'))

    def test_adapter_unauthorized_change_rehashed(self):
        self.mutation_rejected(lambda b,m:(b/'src/k70_xnu_usb.c').write_bytes((b/'src/k70_xnu_usb.c').read_bytes()+b'\n/* unexpected */\n'))

    def test_patch_unauthorized_change_rehashed(self):
        self.mutation_rejected(lambda b,m:(b/'zzzz-k70-usb-log.patch').write_bytes((b/'zzzz-k70-usb-log.patch').read_bytes()+b'\n'))

    def test_uninventoried_file(self):
        self.mutation_rejected(lambda b,m:(b/'unexpected.py').write_text('raise RuntimeError'))

    def test_mode_metadata_tamper_rehashed(self):
        def mutate(bundle,manifest):
            contract=json.loads((bundle/'probe-contract.json').read_text())
            contract['modes']['4']='bad'; manifest['early_probe']=contract
            (bundle/'probe-contract.json').write_text(json.dumps(contract))
        self.mutation_rejected(mutate)

    def test_patch_apply_reverse_twice(self):
        with self.temp() as temporary:
            tree=Path(temporary)
            for relative in ('osfmk/arm/arm_init.c','pexpert/arm/pe_serial.c',
                             'pexpert/arm/pe_kprintf.c','osfmk/console/serial_console.c'):
                text=(PARENT/'reference'/relative).read_text()
                if relative.endswith('arm_init.c'):
                    text=text.replace('\tPE_init_platform(FALSE, args); /* Get platform expert set up */',
                        '\tPE_init_platform(FALSE, args); /* Get platform expert set up */\n\tboot_progress_init();')
                    text=text.replace('\tarm_vm_init(xmaxmem, args);',
                        '\tboot_progress_stage("arm_vm_init enter");\n\tarm_vm_init(xmaxmem, args);\n\tboot_progress_stage("arm_vm_init returned");')
                if relative.endswith('pe_kprintf.c'):
                    text=text.replace('PE_init_kprintf(void)\n{','PE_init_kprintf(void)\n{\n\tif (boot_progress_active()) { PE_kputc = boot_progress_putc; return; }')
                if relative.endswith('serial_console.c'):
                    text=text.replace('_cnputc(char c, bool poll)\n{','_cnputc(char c, bool poll)\n{\n\tif (boot_progress_active()) { boot_progress_putc(c); return; }')
                target=tree/relative; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(text.encode())
            startup=tree/'osfmk/kern/startup.c'; startup.parent.mkdir(parents=True,exist_ok=True)
            startup.write_bytes((PARENT/'reference/osfmk/kern-startup.c').read_text().replace(
                '\tclock_service_create();','\tclock_service_create();\n\tboot_progress_start();').encode())
            probe_patch=str(BUNDLE/'zzzz-k70-usb-log.patch')
            for _ in range(2):
                subprocess.run(['git','-c','core.autocrlf=false','-C',str(tree),'apply','--check',probe_patch],check=True)
                subprocess.run(['git','-c','core.autocrlf=false','-C',str(tree),'apply',probe_patch],check=True)
                for source in (BUNDLE/'src').iterdir():
                    self.assertEqual((tree/'pexpert/arm'/source.name).read_bytes(),source.read_bytes())
                arm=(tree/'osfmk/arm/arm_init.c').read_text()
                self.assertIn('k70_xnu_checkpoint("arm_vm_init enter");\n\tk70_xnu_probe(2);\n\tarm_vm_init',arm)
                subprocess.run(['git','-c','core.autocrlf=false','-C',str(tree),'apply','--reverse','--check',probe_patch],check=True)
                subprocess.run(['git','-c','core.autocrlf=false','-C',str(tree),'apply','--reverse',probe_patch],check=True)

    def test_real_installer_and_derived_hook(self):
        installer=module('prepare_ci')
        base=ROOT/'research/mansar-source-d4dbb368/UniXNU-vermeer-d4dbb3683023a17bb468b9774f52c87f3060e739'
        manifest=validate(BUNDLE)
        with self.temp() as temporary:
            device=Path(temporary)/'device'
            for relative in ['tools/prepare_kernel_patches.py',*manifest['device_fixes']['files']]:
                target=device/relative; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes((base/relative).read_bytes())
            with patch.object(installer.subprocess,'check_output',return_value=installer.DEVICE+'\n'):
                installer.install(device,BUNDLE)
            self.assertTrue((device/'tools/k70-xnu-early-probe/source-manifest.json').exists())
            tree=Path(temporary)/'tree'; upstream=Path(temporary)/'upstream'
            for d in (tree/'scripts',tree/'.cache',upstream/'scripts'): d.mkdir(parents=True,exist_ok=True)
            original=(ROOT/'research/baseline-b6-build-xnu.sh').read_bytes()
            for d in (tree,upstream): (d/'scripts/build-xnu-4k-baseline.sh').write_bytes(original)
            namespace={'Path':Path,'hashlib':hashlib,'shutil':shutil,'__file__':str(device/'tools/prepare_kernel_patches.py')}
            exec('def invoke(local,tree,upstream):\n'+installer.HOOK,namespace)
            local=tree/'patches'; local.mkdir(); namespace['invoke'](local,tree,upstream)
            self.assertEqual((local/'zzzz-k70-usb-log.patch').read_bytes(),(BUNDLE/'zzzz-k70-usb-log.patch').read_bytes())
            self.assertEqual((upstream/'scripts/build-xnu-4k-baseline.sh').read_bytes(),original)

    def test_actual_parent_kernel_cannot_be_relabelled(self):
        verifier=module('verify_kernel')
        parent=ROOT/'out/ci/39906691508/k70-usb-debug-platform-39906691508-1'
        with self.assertRaisesRegex(ValueError,'Missing actual noinline probe symbols'):
            verifier.verify(parent/'kernel.development.vermeer-build.macho',parent/'crypto-hmac.json')

    def test_new_inspector_requires_real_probe_binary_and_exact_identity(self):
        inspector=module('inspect_kernel')
        parent=ROOT/'out/ci/39906691508/k70-usb-debug-platform-39906691508-1'
        bundle_manifest=json.loads((BUNDLE/'source-manifest.json').read_text())
        with self.temp() as temporary:
            directory=Path(temporary)
            for source in parent.iterdir():
                if source.is_file(): shutil.copyfile(source,directory/source.name)
            manifest=json.loads((directory/'usb-debug-manifest.json').read_text())
            manifest.update(kind='k70-xnu-early-probe-source-kernel',
                usb_bundle_manifest=bundle_manifest,
                usb_bundle_manifest_sha256=sha((BUNDLE/'source-manifest.json').read_bytes()),
                patch_sha256=bundle_manifest['files']['zzzz-k70-usb-log.patch'],
                early_probe_version=1,early_probe_symbols=list(inspector.PROBE_SYMBOLS),
                parent_source_manifest_sha256=PARENT_MANIFEST,parent_kernel_sha256=PARENT_KERNEL)
            path=directory/'usb-debug-manifest.json'
            kernel=directory/'kernel.development.vermeer-build.macho'
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'Missing actual noinline probe symbols'):
                inspector.inspect(kernel,path)
            mutations=[('kind','k70-usb-debug-source-kernel'),('early_probe_version',True),
                ('early_probe_version',0),('early_probe_symbols',list(reversed(inspector.PROBE_SYMBOLS))),
                ('parent_source_manifest_sha256','0'*64),('parent_kernel_sha256','0'*64)]
            for key,value in mutations:
                bad=copy.deepcopy(manifest); bad[key]=value; path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): inspector.inspect(kernel,path)
            with self.assertRaisesRegex(ValueError,'requires its bound CI manifest'):
                inspector.inspect(kernel,None)

    def test_separate_workflow_and_export(self):
        exporter=module('export_stage')
        with self.temp() as temporary:
            stage=Path(temporary)/'stage'
            old=ROOT/'ci/repository/.github/workflows/k70-usb-debug.yml'; before=old.read_bytes()
            exporter.export(stage)
            self.assertEqual(old.read_bytes(),before)
            workflow=(stage/'.github/workflows/k70-early-probes.yml').read_text()
            self.assertIn("kind='k70-xnu-early-probe-source-kernel'",workflow)
            self.assertIn('early_probe_version=validation',workflow)
            self.assertNotIn('/xnu-debug/',workflow)
            # Compile the real inline Python sealing block, independent of YAML.
            start=workflow.index('          import hashlib, importlib.util, json, os\n')
            end=workflow.index('\n          PY',start)
            code='\n'.join(line[10:] for line in workflow[start:end].splitlines())
            ast.parse(code)
            validate(stage/'xnu-probes/bundle',stage/'xnu-probes')


if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True)
    unittest.main(verbosity=2)
