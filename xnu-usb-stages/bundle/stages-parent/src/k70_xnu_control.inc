/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Diagnostic command executor. Called only by explicit foreground/worker
 * service points AFTER pump returns, never by a console producer or USB event.
 */
static k70_ctl_mailbox ctl_mailbox;
static k70_ctl_reset_guard ctl_reset;
static uint32_t ctl_exec_lock;
static uint64_t ctl_boot, ctl_ticks_start, ctl_frequency, ctl_arm_serial;
static uint64_t ctl_seen_bad, ctl_seen_busy;
static uint32_t ctl_psci_version;
static int64_t ctl_psci_feature = -1;
static unsigned ctl_psci_conduit; /* 0=absent,1=SMC,2=HVC: no default */
static bool ctl_reset_ready;
static const char *ctl_reset_reason = "not-probed";
static char ctl_bootargs[257];
static bool ctl_bootargs_truncated;

static uint64_t control_counter(void)
{ uint64_t v; __asm__ volatile("mrs %0, cntpct_el0":"=r"(v)); return v; }
static uint64_t control_ms(void)
{
    uint64_t ticks=control_counter()-ctl_ticks_start;
    if (!ctl_frequency) return 0;
    return (ticks/ctl_frequency)*1000U + ((ticks%ctl_frequency)*1000U)/ctl_frequency;
}
static const char *control_phase(void)
{ return thread_started ? "xnu-worker" : "xnu-foreground"; }
static const char *control_conduit(void)
{ return ctl_psci_conduit==1 ? "smc" : ctl_psci_conduit==2 ? "hvc" : "none"; }

/* Standard SMCCC register contract, independent kernel code. The conduit is
 * accepted only from a supplied, host-verified live-FDT-derived /psci node.
 * No firmware function pointer, vendor PMIC register or reset reason is used.
 */
static __attribute__((noinline)) int64_t control_psci(uint32_t function, uint64_t argument)
{
    register uint64_t x0 __asm__("x0")=function;
    register uint64_t x1 __asm__("x1")=argument;
    register uint64_t x2 __asm__("x2")=0;
    register uint64_t x3 __asm__("x3")=0;
    if (ctl_psci_conduit==1) {
        __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
          "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    } else if (ctl_psci_conduit==2) {
        __asm__ volatile("hvc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
          "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    } else return -1;
    /* All used PSCI function IDs are SMC32. Sign-extend its32-bit error value
     * explicitly: firmware is allowed to leave upper x0 bits unspecified. */
    return (int64_t)(int32_t)(uint32_t)x0;
}
static bool control_compatible(const char *value, unsigned bytes)
{
    bool supported=false; unsigned at=0;
    if (!value || !bytes || bytes>256 || value[bytes-1]) return false;
    while (at<bytes) {
        unsigned start=at;
        while (at<bytes && value[at]) at++;
        if (at==bytes) return false;
        if ((at-start==12 && !memcmp(value+start,"arm,psci-1.0",12)) ||
            (at-start==12 && !memcmp(value+start,"arm,psci-0.2",12))) supported=true;
        at++;
    }
    return supported;
}
static void control_probe_reset(void)
{
    DTEntry node; const void *property; unsigned bytes=0;
    ctl_reset_reason="no-psci-node";
    if (SecureDTLookupEntry(NULL,"/psci",&node)!=kSuccess) return;
    ctl_reset_reason="invalid-psci-compatible";
    if (SecureDTGetProperty(node,"compatible",&property,&bytes)!=kSuccess ||
        !control_compatible(property,bytes)) return;
    ctl_reset_reason="invalid-psci-method";
    if (SecureDTGetProperty(node,"method",&property,&bytes)!=kSuccess || bytes!=4) return;
    if (!memcmp(property,"smc",4)) ctl_psci_conduit=1;
    else if (!memcmp(property,"hvc",4)) ctl_psci_conduit=2;
    else return;
    ctl_psci_version=(uint32_t)control_psci(0x84000000U,0); /* PSCI_VERSION */
    ctl_reset_reason="psci-pre-1.0-or-error";
    if ((int32_t)ctl_psci_version<0 || (ctl_psci_version>>16)<1) return;
    ctl_psci_feature=control_psci(0x8400000aU,0x84000009U); /* FEATURES(SYSTEM_RESET) */
    ctl_reset_reason="psci-reset-unsupported";
    if (ctl_psci_feature<0) return;
    ctl_reset_reason="ready"; ctl_reset_ready=true;
}
static __attribute__((noinline)) void control_receive(const uint8_t *data, unsigned bytes)
{
    /* Called under poll_lock; framing and mailbox only. No response, SMC,
     * replay, console call, delay, allocation or command execution here. */
    if (bytes<=RX_BYTES) k70_ctl_feed(&ctl_mailbox,data,bytes);
}
static uint64_t control_line(const char *line, uint64_t *start)
{
    char output[1024]; unsigned n=(unsigned)strlen(line);
    if (n>sizeof(output)-2) n=sizeof(output)-2;
    memcpy(output,line,n); output[n++]='\n';
    /* Return the exact absolute interval of this atomic append. A reset must
     * drain its committed cursor, not cumulative TxBytes (replay inflates it). */
    if (!try_lock(&log_lock)) {
        __atomic_fetch_add(&log_dropped,n,__ATOMIC_RELAXED); return 0;
    }
    if (start) *start=log_total;
    for (unsigned i=0;i<n;i++) kernel_log[(log_total+i)%sizeof(kernel_log)]=(uint8_t)output[i];
    log_total+=n; uint64_t goal=log_total;
    unlock(&log_lock); return goal;
}
static uint64_t control_reply(const k70_ctl_request *request, const char *status, const char *detail, uint64_t *start)
{
    char line[1000];
    snprintf(line,sizeof(line),"K70CTL R id=%016llx boot=%016llx cmd=%s status=%s %s",
      (unsigned long long)request->id,(unsigned long long)ctl_boot,request->command,status,detail);
    return control_line(line,start);
}
static void control_init(boot_args *args)
{
    ctl_ticks_start=control_counter();
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(ctl_frequency));
    if (!ctl_frequency || ctl_frequency>1000000000ULL) ctl_frequency=0;
    ctl_boot=ctl_ticks_start ^ owned_base ^ owned_va ^ owned_bytes;
    if (!ctl_boot) ctl_boot=1;
    unsigned n=0;
    while (n<sizeof(args->CommandLine) && args->CommandLine[n] && n<sizeof(ctl_bootargs)-1) {
        ctl_bootargs[n]=args->CommandLine[n]; n++;
    }
    ctl_bootargs[n]=0;
    ctl_bootargs_truncated=n<sizeof(args->CommandLine) && args->CommandLine[n]!=0;
}
static void control_ready(void)
{
    char line[256];
    if (ctl_frequency) control_probe_reset();
    else ctl_reset_reason="invalid-counter-frequency";
    snprintf(line,sizeof(line),"K70CTL READY version=1 boot=%016llx phase=%s psci=%s reset=%s reason=%s",
      (unsigned long long)ctl_boot,control_phase(),control_conduit(),ctl_reset_ready?"ready":"unavailable",ctl_reset_reason);
    (void)control_line(line,NULL);
}
static const char *control_reset_now(uint64_t ack_start, uint64_t goal)
{
    /* Let the response reach the host if it is reading. This is a bounded
     * best-effort drain, NOT a claim of application-level acknowledgement. */
    uint64_t start=control_ms(); bool committed=false;
    if (!goal) return "ack-not-appended";
    while (control_ms()-start<500) {
        bool drained=false;
        if (try_lock(&poll_lock)) {
            K70UsbCdcPoll();
            if (try_lock(&log_lock)) {
                uint64_t oldest=log_total>sizeof(kernel_log)?log_total-sizeof(kernel_log):0;
                drained=m.Cursor>=goal && oldest<=ack_start && !m.Status.Failed && m.Status.Running;
                unlock(&log_lock);
            }
            unlock(&poll_lock);
        }
        if (drained) { committed=true; break; }
        MicroSecondDelay(1000);
    }
    if (!committed) return "ack-drain-timeout";
    if (!try_lock(&poll_lock)) return "poll-busy";
    EFI_STATUS stopped=StopEngine(); /* DMA object remains owned on timeout. */
    if (EFI_ERROR(stopped) || !m.Status.Halted) { unlock(&poll_lock); return "usb-stop-failed"; }
    __asm__ volatile("dsb sy":::"memory");
    (void)control_psci(0x84000009U,0); /* Standard PSCI SYSTEM_RESET, no storage */
    unlock(&poll_lock);
    /* SYSTEM_RESET must not return. If firmware returns, do not attempt an
     * undocumented PMIC fallback or reuse stopped endpoints. Recovery remains
     * manual; the kernel log records this explicit failure boundary. */
    message("K70CTL reset-returned: PSCI returned; USB stopped; manual recovery required");
    return "psci-returned";
}
static __attribute__((noinline)) void control_service(void)
{
    k70_ctl_request request; K70_USB_CDC_STATUS snapshot; uint64_t bad,busy;
    if (!try_lock(&ctl_exec_lock)) return;
    if (!try_lock(&poll_lock)) { unlock(&ctl_exec_lock); return; }
    bool have=k70_ctl_take(&ctl_mailbox,&request);
    snapshot=m.Status; bad=ctl_mailbox.bad_lines; busy=ctl_mailbox.busy_lines;
    unlock(&poll_lock);
    char detail[760];
    if (bad!=ctl_seen_bad || busy!=ctl_seen_busy) {
        snprintf(detail,sizeof(detail),"K70CTL NOTICE boot=%016llx status=rx_rejected invalid=%llu busy=%llu",
          (unsigned long long)ctl_boot,(unsigned long long)bad,(unsigned long long)busy);
        (void)control_line(detail,NULL); ctl_seen_bad=bad; ctl_seen_busy=busy;
    }
    if (!have) { unlock(&ctl_exec_lock); return; }
    const char *status="ok"; detail[0]=0; bool reset_now=false;
    bool replay=k70_ctl_equal(request.command,"replay");
    bool arm=k70_ctl_equal(request.command,"reboot-arm");
    bool confirm=k70_ctl_equal(request.command,"reboot-confirm");
    if (request.boot && request.boot!=ctl_boot) status="stale_boot";
    else if ((replay || arm || confirm) && request.boot!=ctl_boot) status="denied";
    else if ((confirm && !request.has_argument) || (!confirm && request.has_argument)) status="invalid";
    else if (k70_ctl_equal(request.command,"features")) {
        snprintf(detail,sizeof(detail),"version=1 phase=%s commands=features,info,ping,status,uptime,memory,bootargs,usb,replay,reboot-arm,reboot-confirm reset=%s psci=%s psci_version=%08x psci_feature=%lld reason=%s max_wire=256 mailbox=1",
          control_phase(),ctl_reset_ready?"ready":"unavailable",control_conduit(),ctl_psci_version,(long long)ctl_psci_feature,ctl_reset_reason);
    } else if (k70_ctl_equal(request.command,"info")) {
        snprintf(detail,sizeof(detail),"phase=%s board=vermeer soc=sm8550 serial=K70XNU001 kernel=xnu-10063.141.1 protocol=1",control_phase());
    } else if (k70_ctl_equal(request.command,"ping")) {
        snprintf(detail,sizeof(detail),"pong=1 phase=%s",control_phase());
    } else if (k70_ctl_equal(request.command,"uptime")) {
        snprintf(detail,sizeof(detail),"ms=%llu counter_hz=%llu",(unsigned long long)control_ms(),(unsigned long long)ctl_frequency);
    } else if (k70_ctl_equal(request.command,"memory")) {
        snprintf(detail,sizeof(detail),"owned_base=%llx owned_bytes=%llx dma=%llx dma_bytes=%llx ring_bytes=%x memory_read=unavailable",
          (unsigned long long)owned_base,(unsigned long long)owned_bytes,(unsigned long long)snapshot.DmaAddress,
          (unsigned long long)snapshot.DmaBytes,(unsigned)sizeof(kernel_log));
    } else if (k70_ctl_equal(request.command,"bootargs")) {
        static const char hex[]="0123456789abcdef"; unsigned n=0;
        memcpy(detail,"encoding=hex value=",19); n=19;
        for (unsigned i=0;ctl_bootargs[i];i++) { detail[n++]=hex[(uint8_t)ctl_bootargs[i]>>4]; detail[n++]=hex[(uint8_t)ctl_bootargs[i]&15]; }
        snprintf(detail+n,sizeof(detail)-n," truncated=%u",ctl_bootargs_truncated?1U:0U);
    } else if (k70_ctl_equal(request.command,"usb") || k70_ctl_equal(request.command,"status")) {
        snprintf(detail,sizeof(detail),"phase=%s running=%u configured=%u dtr=%u failed=%u tx=%llu rx=%llu events=%llu ring_total=%llu dropped=%llu rx_invalid=%llu rx_busy=%llu reset=%s psci=%s",
          control_phase(),snapshot.Running,snapshot.Configured,snapshot.Dtr,snapshot.Failed,
          (unsigned long long)snapshot.TxBytes,(unsigned long long)snapshot.RxBytes,(unsigned long long)snapshot.Events,
          (unsigned long long)__atomic_load_n(&log_total,__ATOMIC_RELAXED),(unsigned long long)__atomic_load_n(&log_dropped,__ATOMIC_RELAXED),
          (unsigned long long)bad,(unsigned long long)busy,ctl_reset_ready?"ready":"unavailable",control_conduit());
    } else if (replay) {
        if (!try_lock(&poll_lock)) status="busy";
        else { m.Cursor=0; m.CursorGeneration++; unlock(&poll_lock); snprintf(detail,sizeof(detail),"from=oldest-retained"); }
    } else if (arm || confirm) {
        if (!ctl_reset_ready) { status="unavailable"; snprintf(detail,sizeof(detail),"reason=%s",ctl_reset_reason); }
        else if (arm) {
            uint64_t token=control_counter() ^ ctl_boot ^ request.id ^ (++ctl_arm_serial*0x9e3779b97f4a7c15ULL);
            k70_ctl_arm(&ctl_reset,token,control_ms());
            snprintf(detail,sizeof(detail),"token=%016llx ttl_ms=%u path=psci-%s",(unsigned long long)ctl_reset.token,K70_CTL_TOKEN_TTL_MS,control_conduit());
        } else {
            unsigned accepted=k70_ctl_confirm(&ctl_reset,request.argument,control_ms());
            status=accepted==1?"resetting":accepted==2?"expired":"denied";
            reset_now=accepted==1;
            snprintf(detail,sizeof(detail),"path=psci-%s",control_conduit());
        }
    } else {
        status="unavailable";
        snprintf(detail,sizeof(detail),"phase=%s reason=unsupported-in-this-stage",control_phase());
    }
    uint64_t ack_start=0;
    uint64_t goal=control_reply(&request,status,detail,&ack_start);
    if (reset_now) {
        const char *failure=control_reset_now(ack_start,goal);
        snprintf(detail,sizeof(detail),"reason=%s",failure);
        (void)control_reply(&request,"unavailable",detail,NULL);
    }
    unlock(&ctl_exec_lock);
}
