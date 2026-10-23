/* Fixed-width local state copied from the tested protocol; no firmware calls. */
typedef UINTN (EFIAPI *K70_USB_COPY_LOG)(
  IN OUT UINT64  *Cursor,
  OUT UINT8      *Destination,
  IN UINTN       Capacity
  );

typedef VOID (EFIAPI *K70_USB_LOG_MESSAGE)(IN CONST CHAR8 *Line);

#define K70_USB_VALID_GCC         0x01U
#define K70_USB_VALID_CONTROLLER  0x02U
#define K70_USB_VALID_SMMU        0x04U
#define K70_USB_VALID_IDLE        0x08U
#define K70_USB_VALID_CACHE       0x10U
#define K70_USB_VALID_ROUTE       0x20U
#define K70_USB_VALID_CONTEXT     0x40U
#define K70_USB_VALID_SCAN        0x80U

typedef struct {
  BOOLEAN               Initialized;
  BOOLEAN               Running;
  BOOLEAN               Failed;
  BOOLEAN               Configured;
  BOOLEAN               Dtr;
  BOOLEAN               Halted;
  BOOLEAN               DmaReserved;
  EFI_STATUS            LastStatus;
  EFI_STATUS            ShutdownStatus;
  EFI_PHYSICAL_ADDRESS  DmaAddress;
  UINTN                 DmaBytes;
  UINT32                DmaAddressWidth;
  UINT32                GccPower;
  UINT32                GccMaster;
  UINT32                GccCfg;
  UINT32                GccAggre;
  UINT32                SnpsId;
  UINT32                Gctl;
  UINT32                SmmuRoute;
  UINT32                SmmuCbar;
  UINT32                SmmuSctlr;
  UINT32                ValidFields;
  UINT32                SmmuId0;
  UINT32                SmmuId1;
  UINT32                SmmuControl;
  UINT32                SmmuId2;
  UINT32                ExactMatches;
  UINT32                BroadMatches;
  UINT32                SmmuSmr;
  UINT32                DstsBefore;
  UINT32                DctlBefore;
  UINT32                DstsAfter;
  UINT32                CacheLineBytes;
  UINT64                Events;
  UINT64                Setups;
  UINT64                TxBytes;
  UINT64                RxBytes;
  CHAR8                 LastMessage[96];
} K70_USB_CDC_STATUS;
