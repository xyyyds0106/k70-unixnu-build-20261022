/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * K70 source-kernel log transport. Included once by pexpert/arm/pe_serial.c.
 * All code, 1 MiB RAM ring and DMA are permanent kernel-owned image storage.
 * The USB peripheral is restarted only after arm_vm_init. No UEFI call or
 * function address is present. No storage, clock, PMIC or SMMU writes occur.
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <stdint.h>
#include <stdbool.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <mach/thread_act.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <pexpert/arm/boot.h>
#include <vm/pmap.h>

/* The retained protocol spells its local types as the tested UEFI port did.
 * These are plain kernel-local C aliases. There is no UEFI header or runtime. */
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t UINTN;
typedef char CHAR8;
typedef bool BOOLEAN;
typedef void VOID;
typedef int EFI_STATUS;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
#define STATIC static
#define CONST const
#define EFIAPI
#define IN
#define OUT
#define TRUE true
#define FALSE false
#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 1
#define EFI_ALREADY_STARTED 2
#define EFI_NOT_READY 3
#define EFI_NOT_STARTED 4
#define EFI_UNSUPPORTED 5
#define EFI_TIMEOUT 6
#define EFI_DEVICE_ERROR 7
#define EFI_COMPROMISED_DATA 8
#define EFI_ABORTED 9
#define EFI_ERROR(X) ((X) != 0)
#define K70_USB_DMA_SIZE 0x4000U
#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#ifndef MIN
#define MIN(A,B) ((A) < (B) ? (A) : (B))
#endif
#define CopyMem(D,S,N) memcpy((D),(S),(N))
#define AsciiSPrint snprintf
#define AsciiStrCpyS(D,N,S) strlcpy((D),(S),(N))

#include "k70_usb_status.inc"
#include "k70_usb_guards.inc"

void k70_xnu_early(boot_args *);
void k70_xnu_after_vm(void);
void k70_xnu_write(const char *, unsigned);
void k70_xnu_putc(char);
void k70_xnu_checkpoint(const char *);
void k70_xnu_thread_start(void);
int k70_xnu_enabled(void);

static EFI_STATUS AllocateDma(void);
static EFI_STATUS MapKernelDevices(void);
static UINTN KernelDeviceBase(UINTN);
static void KernelCache(void *, UINTN, BOOLEAN);
static void MicroSecondDelay(UINTN);

/* Exact physical data comes from the loader's BootArgs, never a board guess. */
static uint64_t owned_base, owned_bytes, owned_va;
static bool debug_enabled;
static vm_offset_t usb_va, gcc_va, smmu_va, qscratch_va;
static uint8_t kernel_dma[K70_USB_DMA_SIZE] __attribute__((aligned(0x4000)));
static uint8_t kernel_log[1024U * 1024U];
static uint64_t log_total, log_dropped;
static uint32_t log_lock, poll_lock;
static bool vm_ready, thread_started;
static int sleep_channel;

static bool try_lock(uint32_t *lock)
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(lock, &expected, 1, false,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}
static void unlock(uint32_t *lock)
{ __atomic_store_n(lock, 0, __ATOMIC_RELEASE); }

void k70_xnu_write(const char *data, unsigned bytes)
{
    if (!bytes) return;
    if (!try_lock(&log_lock)) {
        __atomic_fetch_add(&log_dropped, bytes, __ATOMIC_RELAXED);
        return;
    }
    for (unsigned i=0; i<bytes; i++)
        kernel_log[(log_total+i) % sizeof(kernel_log)] = (uint8_t)data[i];
    log_total += bytes;
    unlock(&log_lock);
}

static UINTN copy_log(UINT64 *cursor, UINT8 *data, UINTN capacity)
{
    if (!try_lock(&log_lock)) return 0;
    uint64_t oldest = log_total > sizeof(kernel_log) ? log_total-sizeof(kernel_log) : 0;
    if (*cursor < oldest) *cursor = oldest;
    if (*cursor > log_total) *cursor = log_total;
    UINTN bytes = (UINTN)MIN((uint64_t)capacity, log_total-*cursor);
    for (UINTN i=0; i<bytes; i++)
        data[i] = kernel_log[(*cursor+i) % sizeof(kernel_log)];
    *cursor += bytes;
    unlock(&log_lock);
    return bytes;
}

static void message(const char *line)
{
    k70_xnu_write(line, (unsigned)strlen(line));
    k70_xnu_write("\n", 1);
}

/* KernelDeviceBase replaces the physical identity accesses of the UEFI port. */
static UINTN KernelDeviceBase(UINTN base)
{
    switch (base) {
    case 0x0A600000: return usb_va;
    case 0x00139000: return gcc_va;
    case 0x15000000: return smmu_va;
    case 0x0A6F8800: return qscratch_va;
    default: return 0; /* All callers use one of the four fixed constants. */
    }
}
static EFI_STATUS MapKernelDevices(void)
{
    usb_va = ml_io_map(0x0A600000, 0xE000);
    gcc_va = ml_io_map(0x00139000, 0x1000);
    smmu_va = ml_io_map(0x15000000, 0xD0000);
    qscratch_va = ml_io_map(0x0A6F8800, 0x100);
    return usb_va && gcc_va && smmu_va && qscratch_va ? EFI_SUCCESS : EFI_NOT_READY;
}
static void MicroSecondDelay(UINTN usec)
{
    uint64_t start, now, freq;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    uint64_t ticks = (freq*usec + 999999U) / 1000000U;
    do { __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now)); }
    while (now-start < ticks);
}
static void KernelCache(void *buffer, UINTN bytes, BOOLEAN invalidate)
{
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    UINTN line = 4U << ((ctr >> 16) & 15U);
    UINTN begin = (UINTN)buffer & ~(line-1U);
    UINTN end = (UINTN)buffer + bytes;
    for (UINTN at=begin; at<end; at+=line) {
        if (invalidate) __asm__ volatile("dc ivac, %0" :: "r"(at) : "memory");
        else __asm__ volatile("dc cvac, %0" :: "r"(at) : "memory");
    }
    __asm__ volatile("dsb sy" ::: "memory");
}

#include "k70_usb_transport.inc"

static EFI_STATUS AllocateDma(void)
{
    uint64_t pa = ml_vtophys((vm_offset_t)kernel_dma);
    UINT32 width = m.Status.DmaAddressWidth;
    if (owned_bytes < K70_USB_DMA_SIZE || owned_base > UINT64_MAX-owned_bytes ||
        !pa || (pa & 0x3FFFU) || pa < owned_base ||
        pa-owned_base > owned_bytes-K70_USB_DMA_SIZE || width < 32 || width > 64 ||
        (width < 64 && pa+K70_USB_DMA_SIZE-1 >= (1ULL << width))) return EFI_UNSUPPORTED;
    /* Every 4 KiB subpage must translate to the same contiguous physical object.
     * This also covers kernels whose page size is larger than 4 KiB. */
    for (unsigned offset=0; offset<K70_USB_DMA_SIZE; offset+=0x1000)
        if (ml_vtophys((vm_offset_t)(kernel_dma+offset)) != pa+offset) return EFI_UNSUPPORTED;
    /* The loader uses a linear kernel mapping; verify the BootArgs relation too. */
    if ((uint64_t)(uintptr_t)kernel_dma < owned_va ||
        (uint64_t)(uintptr_t)kernel_dma-owned_va != pa-owned_base) return EFI_UNSUPPORTED;
    memset(kernel_dma, 0, sizeof(kernel_dma));
    m.Dma = kernel_dma;
    m.Status.DmaAddress = pa;
    m.Status.DmaBytes = sizeof(kernel_dma);
    m.Status.DmaReserved = TRUE; /* Permanently owned by the kernel image. */
    KernelCache(kernel_dma, sizeof(kernel_dma), FALSE);
    KernelCache(kernel_dma, sizeof(kernel_dma), TRUE);
    return EFI_SUCCESS;
}

static void pump(void)
{
    if (!vm_ready || !try_lock(&poll_lock)) return;
    K70UsbCdcPoll();
    unlock(&poll_lock);
}
int k70_xnu_enabled(void) { return debug_enabled; }
void k70_xnu_putc(char c)
{
    k70_xnu_write(&c, 1);
    /* A log producer may hold console/kprintf locks with IRQs disabled.
     * It never polls USB, performs a controller command or waits for DTR.
     * The explicit foreground window and then the USB thread drain the ring. */
}
void k70_xnu_checkpoint(const char *stage)
{
    if (!debug_enabled) return;
    message("K70 XNU CHECKPOINT:");
    message(stage);
    pump();
}
void k70_xnu_early(boot_args *args)
{
    int enabled = 0;
    PE_parse_boot_argn("k70_usb", &enabled, sizeof(enabled));
    debug_enabled = enabled == 1;
    owned_base = args->physBase;
    owned_bytes = args->memSize;
    owned_va = args->virtBase;
    if (debug_enabled) {
        message("K70 XNU K70XNU001 boot ring begins / source kernel");
        k70_xnu_checkpoint("PE_init_platform(FALSE) returned; XNU C is executing");
    }
}
void k70_xnu_after_vm(void)
{
    if (!debug_enabled) return;
    vm_ready = true;
    k70_xnu_checkpoint("arm_vm_init returned; starting kernel-owned USB");
    int result = K70UsbCdcInitialize(copy_log, message);
    char line[160];
    snprintf(line, sizeof(line), "K70 XNU initialize result=%d owned=%llx+%llx DMA=%llx ring=%llu dropped=%llu",
             result, (unsigned long long)owned_base, (unsigned long long)owned_bytes,
             (unsigned long long)m.Status.DmaAddress, (unsigned long long)log_total,
             (unsigned long long)__atomic_load_n(&log_dropped, __ATOMIC_RELAXED));
    message(line);
    /* Optional bounded foreground bringup window. No machine waits forever
     * for a PC. 60 seconds covers first Windows inbox-driver binding. */
    int wait_ms = 60000;
    PE_parse_boot_argn("k70_usb_wait_ms", &wait_ms, sizeof(wait_ms));
    if (wait_ms < 0) wait_ms = 0;
    if (wait_ms > 60000) wait_ms = 60000;
    for (int i=0; i<wait_ms && m.Status.Running; i++) {
        pump();
        MicroSecondDelay(1000);
    }
    k70_xnu_checkpoint("USB foreground window ended; continuing real kernel startup");
}
static void usb_thread(void *arg __unused, wait_result_t result __unused)
{
    while (!m.Status.Failed && m.Status.Running) {
        pump();
        uint64_t deadline;
        clock_interval_to_deadline(1, NSEC_PER_MSEC, &deadline);
        (void)assert_wait_deadline(&sleep_channel, THREAD_UNINT, deadline);
        thread_block(THREAD_CONTINUE_NULL);
    }
    thread_terminate(current_thread());
}
void k70_xnu_thread_start(void)
{
    if (!debug_enabled || thread_started || !m.Status.Running) return;
    thread_started = true;
    thread_t thread;
    if (kernel_thread_start(usb_thread, NULL, &thread) != KERN_SUCCESS) {
        Fail(EFI_ABORTED, "K70 XNU: poll thread creation failed; DMA retained");
        return;
    }
    thread_deallocate(thread);
    k70_xnu_checkpoint("kernel USB polling thread started after clock_service_create");
}
