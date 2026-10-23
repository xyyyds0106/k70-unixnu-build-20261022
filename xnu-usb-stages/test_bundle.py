"""No hardware: source lineage, real patch/installer, old-kernel rejection."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch

from bundle_contract import validate, PARENT_MANIFEST, PARENT_KERNEL, sha

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT/'sources/K70XnuUsbStages'
PARENT = ROOT/'sources/K70XnuEarlyProbe'
REFERENCE = ROOT/'sources/K70XnuDebug'
OUT = ROOT/'build/xnu-usb-stage-tests'


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
        self.assertEqual(len(manifest['files']),43)
        self.assertEqual(manifest['usb_stages']['parent_kernel_sha256'],PARENT_KERNEL)

    def test_parent_manifest_tamper(self):
        self.mutation_rejected(lambda b,m:(b/'stages-parent/source-manifest.json').write_bytes(b'{}'))

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
            contract=json.loads((bundle/'usb-stage-contract.json').read_text())
            contract['modes']['4']='bad'; manifest['usb_stages']=contract
            (bundle/'usb-stage-contract.json').write_text(json.dumps(contract))
        self.mutation_rejected(mutate)

    def test_patch_apply_reverse_twice(self):
        with self.temp() as temporary:
            tree=Path(temporary)
            for relative in ('osfmk/arm/arm_init.c','pexpert/arm/pe_serial.c',
                             'pexpert/arm/pe_kprintf.c','osfmk/console/serial_console.c'):
                text=(REFERENCE/'reference'/relative).read_text()
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
            startup.write_bytes((REFERENCE/'reference/osfmk/kern-startup.c').read_text().replace(
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
            self.assertTrue((device/'tools/k70-xnu-usb-stages/source-manifest.json').exists())
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
        parent=ROOT/'out/ci/39912147245/k70-xnu-probes-platform-39912147245-1'
        with self.assertRaisesRegex(ValueError,'Missing actual noinline USB-stage symbols'):
            verifier.verify(parent/'kernel.development.vermeer-build.macho',parent/'crypto-hmac.json')

    def test_real_instruction_stage_order_and_negative_mutations(self):
        verifier=module('verify_kernel')
        addresses={name:0x2000+0x100*i for i,name in enumerate([
            '_MapKernelDevices','_k70_xnu_usb_stage','_CheckSmmu','_AllocateDma','_StopEngine'])}
        words=[]
        def call(name):
            pc=0x1000+4*len(words)
            words.append(0x94000000|(((addresses[name]-pc)//4)&0x3ffffff))
        call('_MapKernelDevices')
        for mode,boundary in [(1,'_CheckSmmu'),(2,'_AllocateDma'),(3,'_StopEngine')]:
            words.append(0x52800000|(mode<<5)); call('_k70_xnu_usb_stage'); call(boundary)
        code=struct.pack('<'+'I'*len(words),*words)
        report=verifier.stage_call_order(code,0x1000,addresses)
        self.assertEqual(report['stage_selectors'],[1,2,3])
        for index in [1,4,7]:
            changed=list(words); changed[index]=0x52800000
            with self.assertRaises(ValueError): verifier.stage_call_order(struct.pack('<'+'I'*len(changed),*changed),0x1000,addresses)
        swapped=dict(addresses)
        swapped['_CheckSmmu'],swapped['_AllocateDma']=addresses['_AllocateDma'],addresses['_CheckSmmu']
        with self.assertRaises(ValueError): verifier.stage_call_order(code,0x1000,swapped)

    def test_boolean_stage_version_rejected(self):
        def mutate(bundle,manifest):
            contract=json.loads((bundle/'usb-stage-contract.json').read_text())
            contract['version']=True; manifest['usb_stages']=contract
            (bundle/'usb-stage-contract.json').write_text(json.dumps(contract))
        self.mutation_rejected(mutate)

    def test_actual_AArch64_object_initialization_call_order(self):
        # Read the real O2 production object from source-syntax.sh. Resolve only
        # in-section CALL26/JUMP26 relocations, never execute privileged code.
        data=(ROOT/'.tmp/xnu-usb-stages-source-tests/k70_xnu_usb.o').read_bytes()
        self.assertEqual(data[:6],b'\x7fELF\x02\x01')
        shoff=struct.unpack_from('<Q',data,40)[0]
        entsize,count=struct.unpack_from('<HH',data,58)
        sections=[struct.unpack_from('<II4QII2Q',data,shoff+i*entsize) for i in range(count)]
        sym_index=next(i for i,s in enumerate(sections) if s[1]==2)
        symtab=sections[sym_index]; strings=sections[symtab[6]]
        symbols=[]; by_name={}
        for at in range(symtab[4],symtab[4]+symtab[5],symtab[9]):
            name,info,other,sect,value,size=struct.unpack_from('<IBBHQQ',data,at)
            end=data.index(b'\0',strings[4]+name,strings[4]+strings[5])
            name=data[strings[4]+name:end].decode()
            symbols.append((name,sect,value,size))
            if name: by_name[name]=(sect,value,size)
        text_index,start,length=by_name['K70UsbCdcInitialize']
        text=sections[text_index]; code=bytearray(data[text[4]:text[4]+text[5]])
        for rel in sections:
            if rel[1]!=4 or rel[7]!=text_index or rel[6]!=sym_index: continue
            for at in range(rel[4],rel[4]+rel[5],rel[9]):
                offset,info,addend=struct.unpack_from('<QQq',data,at)
                kind=info&0xffffffff; name,sect,value,size=symbols[info>>32]
                if kind not in (282,283) or sect!=text_index: continue
                instruction=(0x94000000 if kind==283 else 0x14000000)|(((value+addend-offset)//4)&0x3ffffff)
                struct.pack_into('<I',code,offset,instruction)
        names=['MapKernelDevices','k70_xnu_usb_stage','CheckSmmu','AllocateDma','StopEngine']
        addresses={'_'+name:by_name[name][1] for name in names}
        evidence=module('verify_kernel').stage_call_order(code[start:start+length],start,addresses)
        self.assertEqual(evidence['stage_selectors'],[1,2,3])
        self.assertGreaterEqual(len(evidence['mapping_call_offsets']),1)

    def test_new_inspector_requires_real_probe_binary_and_exact_identity(self):
        inspector=module('inspect_kernel')
        parent=ROOT/'out/ci/39912147245/k70-xnu-probes-platform-39912147245-1'
        bundle_manifest=json.loads((BUNDLE/'source-manifest.json').read_text())
        with self.temp() as temporary:
            directory=Path(temporary)
            for source in parent.iterdir():
                if source.is_file(): shutil.copyfile(source,directory/source.name)
            manifest=json.loads((directory/'usb-debug-manifest.json').read_text())
            manifest.update(kind='k70-xnu-usb-stages-source-kernel',
                usb_bundle_manifest=bundle_manifest,
                usb_bundle_manifest_sha256=sha((BUNDLE/'source-manifest.json').read_bytes()),
                patch_sha256=bundle_manifest['files']['zzzz-k70-usb-log.patch'],
                early_probe_version=1,early_probe_symbols=list(inspector.PROBE_SYMBOLS),
                usb_stage_version=1,usb_stage_symbols=list(inspector.STAGE_SYMBOLS),
                parent_source_manifest_sha256=PARENT_MANIFEST,parent_kernel_sha256=PARENT_KERNEL)
            path=directory/'usb-debug-manifest.json'
            kernel=directory/'kernel.development.vermeer-build.macho'
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'Missing actual noinline USB-stage symbols'):
                inspector.inspect(kernel,path)
            mutations=[('kind','k70-usb-debug-source-kernel'),('usb_stage_version',True),
                ('usb_stage_version',0),('usb_stage_symbols',list(reversed(inspector.STAGE_SYMBOLS))),
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
            old=ROOT/'ci/repository/.github/workflows/k70-early-probes.yml'; before=old.read_bytes()
            exporter.export(stage)
            self.assertEqual(old.read_bytes(),before)
            workflow=(stage/'.github/workflows/k70-usb-stages.yml').read_text()
            self.assertIn("kind='k70-xnu-usb-stages-source-kernel'",workflow)
            self.assertIn('usb_stage_version=validation',workflow)
            self.assertNotIn('/xnu-probes/',workflow)
            # Compile the real inline Python sealing block, independent of YAML.
            start=workflow.index('          import hashlib, importlib.util, json, os\n')
            end=workflow.index('\n          PY',start)
            code='\n'.join(line[10:] for line in workflow[start:end].splitlines())
            ast.parse(code)
            validate(stage/'xnu-usb-stages/bundle',stage/'xnu-usb-stages')


if __name__=='__main__':
    OUT.mkdir(parents=True,exist_ok=True)
    unittest.main(verbosity=2)
