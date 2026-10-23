/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Deliberately selected XNU checkpoint probes. No USB initialization or pump,
 * EFI call/address, PMIC access, storage write or kernel clock-service call.
 * Default mode 0 follows the parent source kernel's normal control flow.
 */
#include "k70_probe_logic.inc"

typedef struct {
    uint64_t boot, counter_start, counter_frequency, counter_reads;
    uint32_t mode, stage, conduit, version;
    int64_t feature, reset_result;
    const char *status;
} k70_probe_observation_t;
static volatile k70_probe_observation_t k70_probe_observation;
static bool k70_probe_attempted;

#if defined(K70_PROBE_OFFLINE_TEST)
/* Host harness only. Real CI verification requires architectural instructions
 * in the linked noinline helpers, so a production build cannot pass with it. */
static uint64_t k70_probe_counter(void);
static uint64_t k70_probe_frequency(void);
#else
static inline __attribute__((always_inline)) uint64_t k70_probe_counter(void)
{ uint64_t value; __asm__ volatile("mrs %0, cntpct_el0":"=r"(value)); return value; }
static inline __attribute__((always_inline)) uint64_t k70_probe_frequency(void)
{ uint64_t value; __asm__ volatile("mrs %0, cntfrq_el0":"=r"(value)); return value; }
#endif

static void k70_probe_init(boot_args *args)
{
    int mode = 0;
    (void)PE_parse_boot_argn("k70_probe", &mode, sizeof(mode));
    k70_probe_observation.mode = k70_probe_mode_valid(mode) ? (uint32_t)mode : 0;
    k70_probe_observation.feature = -1;
    k70_probe_observation.reset_result = -1;
    k70_probe_observation.status = mode == 0 ? "disabled" :
        k70_probe_mode_valid(mode) ? "selected" : "invalid-mode-disabled";
    uint64_t boot = k70_probe_counter() ^ args->physBase ^ args->virtBase ^ args->memSize;
    k70_probe_observation.boot = boot ? boot : 1;
}

static void k70_probe_log(const char *status)
{
    char line[320];
    k70_probe_observation.status = status;
    snprintf(line, sizeof(line),
        "K70PROBE version=1 boot=%016llx mode=%u stage=%u status=%s psci=%s source=adt:/psci psci_version=%08x feature=%lld counter_hz=%llu delay_ms=4000",
        (unsigned long long)k70_probe_observation.boot,
        k70_probe_observation.mode, k70_probe_observation.stage, status,
        k70_probe_observation.conduit == 1 ? "smc" :
        k70_probe_observation.conduit == 2 ? "hvc" : "none",
        k70_probe_observation.version, (long long)k70_probe_observation.feature,
        (unsigned long long)k70_probe_observation.counter_frequency);
    message(line); /* RAM ring only; never a USB poll or an output callback. */
}

/* Independent standard SMCCC. Every called function here is SMC32; upper x0
 * error bits are unspecified, so explicitly sign-extend the 32-bit result.
 * A conduit is accepted only from the actual ADT node, with no default method.
 */
#if defined(K70_PROBE_OFFLINE_TEST)
static int64_t k70_probe_psci(unsigned conduit, uint32_t function, uint64_t argument);
#else
static __attribute__((noinline)) int64_t k70_probe_psci(unsigned conduit,
                                                      uint32_t function,
                                                      uint64_t argument)
{
    register uint64_t x0 __asm__("x0") = function;
    register uint64_t x1 __asm__("x1") = argument;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    if (conduit == 1) {
        __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
            "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    } else if (conduit == 2) {
        __asm__ volatile("hvc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
            "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    } else return -1;
    return (int64_t)(int32_t)(uint32_t)x0;
}
#endif

static __attribute__((noinline)) bool k70_probe_wait(uint64_t frequency)
{
    k70_probe_clock clock;
    uint64_t counter = k70_probe_counter();
    if (!k70_probe_clock_begin(&clock, frequency, counter)) return false;
    k70_probe_observation.counter_start = counter;
    int result;
    do {
        counter = k70_probe_counter();
        result = k70_probe_clock_step(&clock, counter, k70_probe_frequency());
    } while (result == 0);
    k70_probe_observation.counter_reads = clock.reads;
    return result == 1;
}

__attribute__((noinline)) void k70_xnu_probe(unsigned stage)
{
    if (stage < 1 || stage > 3 || k70_probe_observation.mode != stage ||
        k70_probe_attempted) return;
    k70_probe_attempted = true;
    k70_probe_observation.stage = stage;
    k70_probe_log("checkpoint-entered");

    DTEntry node;
    const void *property;
    unsigned bytes = 0;
    if (SecureDTLookupEntry(NULL, "/psci", &node) != kSuccess) {
        k70_probe_log("no-psci-node"); return;
    }
    if (SecureDTGetProperty(node, "compatible", &property, &bytes) != kSuccess ||
        !k70_probe_compatible(property, bytes)) {
        k70_probe_log("invalid-psci-compatible"); return;
    }
    if (SecureDTGetProperty(node, "status", &property, &bytes) == kSuccess &&
        !k70_probe_status_enabled(property, bytes)) {
        k70_probe_log("psci-node-disabled"); return;
    }
    if (SecureDTGetProperty(node, "method", &property, &bytes) != kSuccess ||
        !(k70_probe_observation.conduit = k70_probe_method(property, bytes))) {
        k70_probe_log("invalid-psci-method"); return;
    }
    k70_probe_observation.counter_frequency = k70_probe_frequency();
    if (k70_probe_observation.counter_frequency < 1000000ULL ||
        k70_probe_observation.counter_frequency > 1000000000ULL) {
        k70_probe_log("invalid-counter-frequency"); return;
    }
    unsigned conduit = k70_probe_observation.conduit;
    uint32_t version = (uint32_t)k70_probe_psci(conduit, 0x84000000U, 0);
    k70_probe_observation.version = version;
    if ((int32_t)version < 0 || (version >> 16) < 1) {
        k70_probe_log("psci-pre-1.0-or-error"); return;
    }
    int64_t feature = k70_probe_psci(conduit, 0x8400000aU, 0x84000009U);
    k70_probe_observation.feature = feature;
    if (feature < 0) { k70_probe_log("psci-reset-unsupported"); return; }
    k70_probe_log("delay-start");
    if (!k70_probe_wait(k70_probe_observation.counter_frequency)) {
        k70_probe_log("counter-or-iteration-failed"); return;
    }
    k70_probe_log("reset-requested");
#if !defined(K70_PROBE_OFFLINE_TEST)
    __asm__ volatile("dsb sy":::"memory");
#endif
    k70_probe_observation.reset_result = k70_probe_psci(conduit, 0x84000009U, 0);
    /* A returning firmware reset is a failure, not a successful checkpoint
     * reset. Keep normal flow and all ordinary USB/POST/security gates intact. */
    k70_probe_log("reset-returned-normal-flow");
}
