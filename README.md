# K70 XNU source build

Manual macOS CI for pinned public UniXNU and Redmi K70 source repositories.

The `platform` build passed on 2026-10-22: [run 39801380604](https://github.com/xyyyds0106/k70-unixnu-build-20261022/actions/runs/39801380604),
build commit `ecc325019f99d9491c15893f89c5e3703543b8ae`.
Compilation, real ArmDTPlatform/ArmCpu linking, source-crypto HMAC and symbol
collection, and artifact upload completed successfully on macos-15.

Run **K70 pinned source kernel** in Actions. `platform` builds the source kernel
with real ArmDTPlatform, ArmCpu and architectural timer support; `source` builds
the smaller source-only baseline. Logs, symbols, HMAC evidence and checksums are
retained with the kernel candidate.

This repository contains no phone partition backups, platform seed or user data.
The workflow does not build a complete OS image, run a phone or flash partitions.
Successful compilation does not establish K70 boot, root, display, touch or GPU support.
Separately, the connected K70 reached the UniXNU UEFI menu. That firmware test
does not show this XNU kernel executing.

The workflow pins the device and core source revisions and records the actual
macOS/Xcode/SDK/compiler versions for each run.

Public DriverKit and TrustCache header listings are fetched with the workflow's
read-only GitHub token to avoid the shared runner's anonymous API rate limit.
Their source tags still come from the pinned feeds, and the unchanged upstream
header preparer verifies each downloaded file against its recorded Git blob hash.
The token is not stored in artifacts or added to the source repositories.
