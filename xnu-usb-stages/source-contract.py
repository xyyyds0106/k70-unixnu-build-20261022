"""Pure derivation of the controlled pre-controller USB diagnostic overlay.

All production source edits are generated from the exact frozen Early parent.
No import, expected_sources(), or build_patch() writes files or touches devices.
"""
import difflib
import hashlib
import json
from pathlib import Path

PARENT_MANIFEST = 'd3306df76cd9d4571502199594b204b58528b7f6b187f89ced7cdee792bdc246'
STAGE_SYMBOLS = ['_k70_xnu_usb_stage', '_k70_xnu_usb_stage_reset', '_k70_probe_reset_core']
STAGE_MARKER = 'K70USBSTAGE version=1'
PATCH = 'zzzz-k70-usb-log.patch'

STAGE_LOGIC = r'''/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Bounded, exact diagnostic command-line selection. No architectural access.
 * A present but invalid stage suppresses every legacy early reset probe.
 */
typedef struct {
    bool present, valid;
    unsigned mode;
} k70_usb_stage_selection;

static inline bool k70_usb_stage_prefix(const char *text, size_t bytes,
                                        const char *key, size_t key_bytes)
{
    if (bytes < key_bytes) return false;
    for (size_t i = 0; i < key_bytes; i++) if (text[i] != key[i]) return false;
    return true;
}
static inline bool k70_usb_stage_digit(const char *text, size_t bytes,
                                       size_t key_bytes, unsigned *value)
{
    if (bytes != key_bytes + 2 || text[key_bytes] != '=' ||
        text[key_bytes + 1] < '0' || text[key_bytes + 1] > '3') return false;
    *value = (unsigned)(text[key_bytes + 1] - '0');
    return true;
}
static inline k70_usb_stage_selection k70_usb_stage_select(const char *line,
                                                           size_t capacity)
{
    k70_usb_stage_selection result = {false, false, 0};
    unsigned stages = 0, probes = 0, usbs = 0, handoffs = 0;
    unsigned probe = 0, usb = 0, handoff = 0;
    bool bad = false;
    size_t end = 0;
    while (end < capacity && line[end]) end++;
    bool terminated = end < capacity;
    for (size_t at = 0; at < end;) {
        while (at < end && (line[at] == ' ' || line[at] == '\t')) at++;
        size_t begin = at;
        while (at < end && line[at] != ' ' && line[at] != '\t') at++;
        size_t bytes = at - begin;
        const char *token = line + begin;
        if (!bytes) continue;
        if (k70_usb_stage_prefix(token, bytes, "k70_usb_stage", 13)) {
            stages++;
            if (!k70_usb_stage_digit(token, bytes, 13, &result.mode)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_probe", 9)) {
            probes++;
            if (!k70_usb_stage_digit(token, bytes, 9, &probe)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_handoff_probe", 17)) {
            handoffs++;
            if (!k70_usb_stage_digit(token, bytes, 17, &handoff)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_usb", 7) &&
                   (bytes == 7 || token[7] == '=')) {
            usbs++;
            if (!k70_usb_stage_digit(token, bytes, 7, &usb)) bad = true;
        }
    }
    result.present = stages != 0 || !terminated;
    result.valid = result.present && terminated && !bad && stages == 1 &&
        result.mode >= 1 && result.mode <= 3 && probes == 1 && probe == 3 &&
        usbs == 1 && usb == 1 && (handoffs == 0 || (handoffs == 1 && handoff == 0));
    return result;
}
'''

STAGE_RUNTIME = r'''/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Executed only at the three no-controller-write initialization checkpoints.
 * All output below appends to the permanent RAM ring; it never pumps USB.
 */
static __attribute__((noinline)) void k70_usb_stage_init(boot_args *args)
{
    usb_stage_selection = k70_usb_stage_select(args->CommandLine,
                                               sizeof(args->CommandLine));
}

static void k70_usb_stage_log(unsigned stage, const char *status)
{
    char line[256];
    snprintf(line, sizeof(line),
        "K70USBSTAGE version=1 boot=%016llx requested=%u reached=%u status=%s controller_touched=%u delay_ms=4000",
        (unsigned long long)k70_probe_observation.boot,
        usb_stage_selection.mode, stage, status, (unsigned)m.ControllerTouched);
    message(line);
}

__attribute__((noinline)) void k70_xnu_usb_stage_reset(unsigned stage)
{
    if (!usb_stage_selection.present || !usb_stage_selection.valid ||
        stage < 1 || stage > 3 || stage != usb_stage_selection.mode ||
        k70_probe_observation.mode != 3 || k70_probe_attempted || !vm_ready ||
        !m.Attempted || m.ControllerTouched || m.Status.Running || m.Status.Failed)
        return;
    k70_usb_stage_log(stage, "checkpoint-entered");
    /* The shared, unchanged PSCI/counter core records stages 4/5/6. The old
     * early C1/C2/C3 wrapper is disabled whenever any stage flag is present. */
    k70_probe_reset_core(stage + 3);
    k70_usb_stage_log(stage, "reset-core-returned");
}

__attribute__((noinline)) bool k70_xnu_usb_stage(unsigned stage)
{
    if (!usb_stage_selection.present) return false;
    if (!usb_stage_selection.valid) {
        k70_usb_stage_log(stage, "invalid-selection-abort-untouched");
        return true;
    }
    if (stage != usb_stage_selection.mode) return false;
    k70_xnu_usb_stage_reset(stage);
    /* A refused/failed/returning reset must not fall through and touch the
     * controller. The Initialize caller immediately returns EFI_ABORTED. */
    return true;
}
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Exact frozen source context differs: ' + repr(old))
    return text.replace(old, new)


def check_parent(parent_bundle):
    raw = (parent_bundle / 'source-manifest.json').read_bytes()
    if sha(raw) != PARENT_MANIFEST:
        raise ValueError('Frozen Early source manifest differs')
    manifest = json.loads(raw)
    actual = {p.relative_to(parent_bundle).as_posix() for p in parent_bundle.rglob('*') if p.is_file()}
    if actual != set(manifest['files']) | {'source-manifest.json'}:
        raise ValueError('Frozen Early inventory differs')
    for name, expected in manifest['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or sha((parent_bundle / path).read_bytes()) != expected:
            raise ValueError('Frozen Early bytes differ: ' + name)
    return manifest


def expected_sources(parent_bundle):
    parent_bundle = Path(parent_bundle)
    check_parent(parent_bundle)
    src = {p.name: p.read_bytes() for p in (parent_bundle / 'src').iterdir() if p.is_file()}
    text = src['k70_xnu_usb.c'].decode()
    text = once(text, '#include "k70_ctl_protocol.inc"', '#include "k70_ctl_protocol.inc"\n#include "k70_usb_stage_logic.inc"')
    text = once(text, 'static EFI_STATUS MapKernelDevices(void);', 'static EFI_STATUS MapKernelDevices(void);\nstatic void k70_usb_stage_init(boot_args *);\n__attribute__((noinline)) bool k70_xnu_usb_stage(unsigned);\n__attribute__((noinline)) void k70_xnu_usb_stage_reset(unsigned);')
    text = once(text, 'static bool debug_enabled;', 'static bool debug_enabled;\nstatic k70_usb_stage_selection usb_stage_selection;')
    for name in ('MapKernelDevices', 'AllocateDma'):
        text = once(text, 'static EFI_STATUS ' + name + '(void)\n{', 'static __attribute__((noinline)) EFI_STATUS ' + name + '(void)\n{')
    text = once(text, '#include "k70_xnu_probe.inc"', '#include "k70_xnu_probe.inc"\n#include "k70_xnu_usb_stages.inc"')
    text = once(text, '    k70_probe_init(args);', '    k70_usb_stage_init(args);\n    k70_probe_init(args);')
    src['k70_xnu_usb.c'] = text.encode()
    text = src['k70_xnu_probe.inc'].decode()
    text = once(text, '__attribute__((noinline)) void k70_xnu_probe(unsigned stage)\n{\n    if (stage < 1 || stage > 3 || k70_probe_observation.mode != stage ||\n        k70_probe_attempted) return;',
        'static __attribute__((noinline)) void k70_probe_reset_core(unsigned stage)\n{\n    if (k70_probe_attempted) return;')
    text += '\n__attribute__((noinline)) void k70_xnu_probe(unsigned stage)\n{\n    if (usb_stage_selection.present || stage < 1 || stage > 3 ||\n        k70_probe_observation.mode != stage) return;\n    k70_probe_reset_core(stage);\n}\n'
    src['k70_xnu_probe.inc'] = text.encode()
    text = src['k70_usb_transport.inc'].decode()
    for signature in ('STATIC EFI_STATUS StopEngine (VOID)', 'STATIC BOOLEAN CheckSmmu (VOID)', 'STATIC EFI_STATUS K70UsbCdcInitialize (K70_USB_COPY_LOG CopyLog, K70_USB_LOG_MESSAGE LogMessage)'):
        text = once(text, signature, signature.replace('STATIC ', 'STATIC __attribute__((noinline)) ', 1))
    text = once(text, '  __asm__ __volatile__ ("mrs %0, ctr_el0" : "=r" (Ctr));',
        '  if (k70_xnu_usb_stage (1)) {\n    Fail (EFI_ABORTED, "K70 XNU USB: U1 probe returned; controller untouched");\n    return EFI_ABORTED;\n  }\n  __asm__ __volatile__ ("mrs %0, ctr_el0" : "=r" (Ctr));')
    text = once(text, '  Status = AllocateDma ();',
        '  if (k70_xnu_usb_stage (2)) {\n    Fail (EFI_ABORTED, "K70 XNU USB: U2 probe returned; controller untouched");\n    return EFI_ABORTED;\n  }\n  Status = AllocateDma ();')
    text = once(text, '  m.ControllerTouched = TRUE;',
        '  if (k70_xnu_usb_stage (3)) {\n    Fail (EFI_ABORTED, "K70 XNU USB: U3 probe returned; controller untouched");\n    return EFI_ABORTED;\n  }\n  m.ControllerTouched = TRUE;')
    src['k70_usb_transport.inc'] = text.encode()
    src['k70_usb_stage_logic.inc'] = STAGE_LOGIC.encode()
    src['k70_xnu_usb_stages.inc'] = STAGE_RUNTIME.encode()
    return src


def build_patch(parent_bundle):
    parent_bundle = Path(parent_bundle)
    src = expected_sources(parent_bundle)
    prefix = (parent_bundle / PATCH).read_text().split('--- /dev/null\n', 1)[0]
    for name, data in sorted(src.items()):
        prefix += ''.join(difflib.unified_diff([], data.decode().splitlines(True),
            fromfile='/dev/null', tofile='b/pexpert/arm/' + name, n=1))
    return prefix.encode()


if __name__ == '__main__':
    parent = Path(__file__).resolve().parents[2] / 'sources/K70XnuEarlyProbe'
    print(json.dumps({'parent_manifest_sha256': PARENT_MANIFEST,
        'sources': {k: sha(v) for k, v in expected_sources(parent).items()},
        'patch_sha256': sha(build_patch(parent))}, indent=2))
