static inline BOOLEAN
K70UsbStreamCovers40 (UINT32 Smr)
{
  UINT32 Mask = (Smr >> 16) & 0x7FFFU;
  return ((Smr & 0x80000000U) != 0) && (((Smr ^ 0x40U) & ~Mask & 0xFFFFU) == 0);
}

static inline BOOLEAN
K70UsbExactStream40 (UINT32 Smr)
{
  return ((Smr & 0x80000000U) != 0) && ((Smr & 0xFFFFU) == 0x40U) &&
         (((Smr >> 16) & 0x7FFFU) == 0);
}

static inline BOOLEAN
K70UsbRouteIdentity (UINT32 Route, UINT32 Cbar, UINT32 Sctlr)
{
  UINT32 Type = (Route >> 16) & 3U;
  return (Type == 1) || ((Type == 0) && (((Cbar >> 16) & 3U) == 1) && ((Sctlr & 1U) == 0));
}

static inline BOOLEAN
K70UsbGccReady (UINT32 Power, UINT32 Master, UINT32 Cfg, UINT32 Aggre)
{
  return ((Power & 0x80000000U) != 0) && (((Master | Cfg | Aggre) & 0x80000000U) == 0);
}

/* Successful data completion can count bytes without advancing a newer replay.
   A failed/stopped session must pass Success=FALSE. */
static inline BOOLEAN
K70UsbCommitPending (
  UINT64 *Cursor, UINT64 CurrentGeneration, UINT64 PendingGeneration,
  UINT64 PendingCursor, UINTN Expected, UINTN Completed, BOOLEAN Success)
{
  if (!Success || (Expected == 0) || (Completed != Expected)) {
    return FALSE;
  }
  if (CurrentGeneration == PendingGeneration) {
    *Cursor = PendingCursor;
  }
  return TRUE;
}
