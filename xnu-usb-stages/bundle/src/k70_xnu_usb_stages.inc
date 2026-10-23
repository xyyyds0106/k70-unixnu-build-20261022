/* SPDX-License-Identifier: BSD-2-Clause-Patent
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
