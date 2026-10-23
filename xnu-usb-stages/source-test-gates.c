/* Exact production Initialize/Map/SMMU/DMA/Fail/reset bodies are generated
 * into actual-functions.inc. Only privileged reads and external APIs are
 * mocked. A returning reset must leave the real controller-write path idle. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define K70_PROBE_OFFLINE_TEST 1
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64;
typedef uintptr_t UINTN; typedef char CHAR8; typedef bool BOOLEAN; typedef void VOID;
typedef int EFI_STATUS; typedef uint64_t EFI_PHYSICAL_ADDRESS;
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
#define EFI_ABORTED 9
#define EFI_ERROR(X) ((X)!=0)
#define K70_USB_DMA_SIZE 0x4000U
#define AsciiSPrint snprintf
static size_t local_copy(char *d,const char *s,size_t n) { size_t b=strlen(s); if(n) { size_t c=b<n-1?b:n-1; memcpy(d,s,c);d[c]=0; } return b; }
#define AsciiStrCpyS(D,N,S) local_copy(D,S,N)
#include "k70_usb_status.inc"
#include "k70_usb_guards.inc"
#include "k70_usb_stage_logic.inc"
#include "actual-state.inc"
typedef struct { uint64_t physBase,virtBase,memSize; char CommandLine[1024]; } boot_args;
typedef uintptr_t vm_offset_t;
typedef void *DTEntry;
#define kSuccess 1
static k70_usb_stage_selection usb_stage_selection;
static uint8_t kernel_dma[K70_USB_DMA_SIZE] __attribute__((aligned(0x4000)));
static uint64_t owned_base,owned_bytes,owned_va;
static uintptr_t usb_va,gcc_va,smmu_va,qscratch_va;
static bool vm_ready;
static unsigned maps,reads,writes,cache_calls,vtophys_calls,reset_calls,psci_calls,dsts_reads,requested_mode;
static unsigned fault;
static uint64_t counter,frequency,dma_pa;
static int feature;
static char last_line[512];
enum { OK,MAP_FAIL,CACHE_BAD,GCC_BAD,ID_BAD,ROLE_BAD,WIDTH_BAD,SMMU_BAD,SMR_BROAD,SMR_DUP,ROUTE_BAD,IDLE_BEFORE_BAD,IDLE_AFTER_BAD,RUN_BAD,DMA_UNALIGNED,DMA_RANGE,DMA_NONLINEAR,DMA_VA_BAD };
static bool k70_xnu_usb_stage(unsigned);
static void k70_xnu_usb_stage_reset(unsigned);
static void message(const char *s) { assert(strlen(s)<sizeof(last_line)); strcpy(last_line,s); }
static void Message(const char *s) { if(m.LogMessage) m.LogMessage(s); }
static uintptr_t ml_io_map(uintptr_t pa,size_t bytes) { assert(bytes); maps++; if(fault==MAP_FAIL && maps==2) return 0; return pa+0x100000000ULL; }
static uint64_t ml_vtophys(vm_offset_t va) { vtophys_calls++; size_t off=va-(uintptr_t)kernel_dma; assert(off<K70_USB_DMA_SIZE); return dma_pa+off+((fault==DMA_NONLINEAR && off==0x1000)?0x1000:0); }
static void KernelCache(void *p,UINTN bytes,BOOLEAN invalidate) { assert(p==kernel_dma && bytes==sizeof(kernel_dma)); assert(invalidate==(cache_calls==1)); cache_calls++; }
static void MicroSecondDelay(UINTN us) { assert(us); }
static UINT32 ReadAt(UINTN base,UINTN off)
{
    reads++;
    if(base==GCC_BASE) return off==4?(fault==GCC_BAD?0:0x80000000U):0;
    if(base==SMMU_BASE) {
        if(off==0x20) return fault==SMMU_BAD?0:0x4C017E69U;
        if(off==0x24) return 0x60000046U;
        if(off==0) return 0x00280406U;
        if(off==0x28) return 0x5111U;
        if(off>=0x800 && off<0x800+105*4) { if(off==0x800) return 0x80000040U; if(off==0x804 && fault==SMR_BROAD) return 0x80010040U; if(off==0x804 && fault==SMR_DUP) return 0x80000040U; return 0; }
        if(off>=0xC00 && off<0xC00+105*4) return fault==ROUTE_BAD?(3U<<16):(1U<<16);
    }
    fprintf(stderr,"Unexpected modeled register base=%lx off=%lx\n",(unsigned long)base,(unsigned long)off); abort();
}
static UINT32 ReadUsb(UINTN off)
{
    reads++;
    if(off==0xC120) return fault==ID_BAD?0:0x55330000U;
    if(off==0xC140) return (fault==WIDTH_BAD?31U:40U)<<24;
    if(off==GCTL) return (fault==ROLE_BAD?1U:2U)<<12;
    if(off==DSTS) { dsts_reads++; return ((fault==IDLE_BEFORE_BAD && dsts_reads==1)||(fault==IDLE_AFTER_BAD && dsts_reads==2))?0:HALTED; }
    if(off==DCTL) return fault==RUN_BAD?RUN:0;
    abort();
}
static void WriteUsb(UINTN off,UINT32 value) { (void)off;(void)value; writes++; abort(); }
static void WriteAt(UINTN base,UINTN off,UINT32 value) { (void)base;(void)off;(void)value; writes++; abort(); }
static bool Command(UINTN ep,UINT32 c,UINT32 p0,UINT32 p1,UINT32 p2) { (void)ep;(void)c;(void)p0;(void)p1;(void)p2; abort(); }
static void ArmSetup(void) { abort(); }
static int PE_parse_boot_argn(const char *name,void *value,int bytes) { assert(!strcmp(name,"k70_probe") && bytes==(int)sizeof(int)); memcpy(value,&requested_mode,sizeof(int)); return 1; }
static int SecureDTLookupEntry(DTEntry ignored,const char *path,DTEntry *node) { (void)ignored; assert(!strcmp(path,"/psci"));*node=(void *)1;return kSuccess; }
static int SecureDTGetProperty(DTEntry node,const char *name,const void **value,unsigned *bytes) { assert(node==(void *)1); if(!strcmp(name,"status"))return 0; if(!strcmp(name,"compatible")){*value="arm,psci-1.0";*bytes=13;return kSuccess;} assert(!strcmp(name,"method"));*value="smc";*bytes=4;return kSuccess; }
#include "k70_xnu_probe.inc"
#include "k70_xnu_usb_stages.inc"
static uint64_t k70_probe_counter(void) { counter+=19200; return counter; }
static uint64_t k70_probe_frequency(void) { return frequency; }
static int64_t k70_probe_psci(unsigned conduit,uint32_t fn,uint64_t arg) { assert(conduit==1);psci_calls++;if(fn==0x84000000U){assert(!arg);return 0x10001;}if(fn==0x8400000aU){assert(arg==0x84000009U);return feature;}assert(fn==0x84000009U&&!arg);assert(counter-k70_probe_observation.counter_start>=frequency*4);reset_calls++;return -1; }
static UINTN copy_log(UINT64 *cursor,UINT8 *data,UINTN cap) { (void)cursor;(void)data;(void)cap;return 0; }
#include "actual-functions.inc"
static void begin(unsigned selected,unsigned bad)
{
    memset(&m,0,sizeof(m)); memset((void *)&k70_probe_observation,0,sizeof(k70_probe_observation));k70_probe_attempted=false;
    fault=bad;maps=reads=writes=cache_calls=vtophys_calls=reset_calls=psci_calls=dsts_reads=0;frequency=19200000;counter=100000;feature=0;vm_ready=true;requested_mode=3;
    owned_base=0xE7E04000ULL;owned_bytes=0x10000000ULL;dma_pa=0xE8000000ULL;
    if(bad==DMA_UNALIGNED) dma_pa++;
    if(bad==DMA_RANGE) dma_pa=owned_base+owned_bytes;
    owned_va=(uintptr_t)kernel_dma-(dma_pa-owned_base)+(bad==DMA_VA_BAD?0x1000:0);
    boot_args args={.physBase=owned_base,.virtBase=owned_va,.memSize=owned_bytes};snprintf(args.CommandLine,sizeof(args.CommandLine),"k70_probe=3 k70_usb=1 k70_usb_stage=%u",selected);
    k70_usb_stage_init(&args);k70_probe_init(&args); assert(usb_stage_selection.present);
}
int main(void)
{
    for(unsigned mode=1;mode<=3;mode++) {
        begin(mode,OK);usb_stage_selection=(k70_usb_stage_selection){false,false,0};k70_probe_observation.mode=mode;
        for(unsigned stage=1;stage<=3;stage++) if(stage!=mode) k70_xnu_probe(stage);
        assert(!psci_calls);assert(!k70_xnu_usb_stage(1)&&!k70_xnu_usb_stage(2)&&!k70_xnu_usb_stage(3));
        k70_xnu_probe(mode);assert(reset_calls==1&&psci_calls==3&&k70_probe_observation.stage==mode);k70_xnu_probe(mode);assert(reset_calls==1);
    }
    begin(1,OK);usb_stage_selection=(k70_usb_stage_selection){false,false,0};k70_probe_observation.mode=0;k70_xnu_probe(1);k70_xnu_probe(2);k70_xnu_probe(3);assert(!psci_calls);
    for(unsigned stage=1;stage<=3;stage++) {
        begin(stage,OK); assert(usb_stage_selection.valid);k70_xnu_probe(1);k70_xnu_probe(2);k70_xnu_probe(3);assert(!psci_calls);
        assert(K70UsbCdcInitialize(copy_log,message)==EFI_ABORTED);assert(reset_calls==1&&psci_calls==3&&maps==4&&!writes&&!m.ControllerTouched&&!m.Status.Running);assert(k70_probe_observation.stage==stage+3);
        assert((stage==1 && !reads && !cache_calls)||(stage==2 && reads && !cache_calls)||(stage==3 && reads && cache_calls==2 && vtophys_calls==5));
        assert(K70UsbCdcInitialize(copy_log,message)==EFI_ALREADY_STARTED);assert(reset_calls==1);
    }
    for(unsigned bad=MAP_FAIL;bad<=DMA_VA_BAD;bad++) {
        begin(3,bad);EFI_STATUS st=K70UsbCdcInitialize(copy_log,message);assert(st!=EFI_SUCCESS&&st!=EFI_ALREADY_STARTED);assert(!reset_calls&&!writes&&!m.ControllerTouched&&!m.Status.Running);
    }
    for(unsigned stage=1;stage<=3;stage++) { begin(stage,OK);feature=-1;assert(K70UsbCdcInitialize(copy_log,message)==EFI_ABORTED);assert(!reset_calls&&!writes&&!m.ControllerTouched); }
    begin(0,OK);assert(!usb_stage_selection.valid);k70_xnu_probe(3);assert(!psci_calls);assert(K70UsbCdcInitialize(copy_log,message)==EFI_ABORTED);assert(!reads&&!writes&&!reset_calls);
    begin(1,OK);requested_mode=1;k70_probe_observation.mode=1;usb_stage_selection.valid=false;k70_xnu_probe(1);assert(!psci_calls);assert(K70UsbCdcInitialize(copy_log,message)==EFI_ABORTED);assert(!writes&&!reset_calls);
    begin(2,OK);m.ControllerTouched=true;m.Attempted=true;k70_xnu_usb_stage_reset(2);assert(!psci_calls);m.ControllerTouched=false;m.Status.Running=true;k70_xnu_usb_stage_reset(2);assert(!psci_calls);
    puts("PASS actual Initialize/Map/SMMU/DMA/reset bodies: U1/U2/U3 exact progress, all guards reject, legacy modes preserved without stage, C3 suppressed with stage, returning/denied reset and invalid stage abort without controller writes");
}
