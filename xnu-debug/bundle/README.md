# K70 XNU USB 日志实验

目标固定源为 XNU `d8b80295118ef25ac3a784134bcf95cd8e88109f`、UniXNU
`b6ae99c17194e6a18fd819d3148e69fe405e91fc` 和 device
`d4dbb3683023a17bb468b9774f52c87f3060e739`，保持原 platform 配置、源码
corecrypto POST 与最终 HMAC 封装。新串口为 VID:PID `1209:0001`、序号
`K70XNU001`，与固件 `K70UEFI001` 分开记录。

本目录是待 CI 编译及实机验证的源码输入。不能把旧 UEFI/HWR 串口成功当成
新内核串口或 XNU 执行成功。

`src/k70_xnu_usb.c` 自带 1 MiB 内存日志环与 16 KiB 对齐 DMA 静态 BSS，
永久属于 loader 分配的内核 image。早期检查点从
`PE_init_platform(FALSE)` 返回后开始，另记录 `arm_vm_init` 进入和返回。
普通 console、kprintf 与 panic 输出进入环。未连接电脑不会阻塞日志生产。
USB 控制器初始化只在 `arm_vm_init` 返回后执行。

内核使用 `ml_io_map` 创建自身设备映射，使用 `ml_vtophys` 核对每个 4 KiB
DMA 子页连续和 BootArgs 的实际 `physBase/virtBase/memSize` 归属关系，再核
AWIDTH；没有旧移植固定高地址假设，也不复用固件 DMA。缓存使用 EL1
`dc cvac` 提交和 `dc ivac` 完成读取，DMA/TRB 独立缓存行，支持上限 64 字节。
协议状态机来自本项目已经 K70 实测的 HWR 版本，生成源 SHA 写在 `.inc` 顶部。

USB 会核对 ABL 保留的 GCC 开关、DWC3 device role、精确 SID 0x40 与 identity
route；任何覆盖 SID 的 broad SMR 都拒绝。保持初始 HALTED/RUN=0 要求，
固件在 ExitBootServices 前必须确认停机。只操作 DWC3 和已经核实的
QSCRATCH VBUS/session override，不改 clock/PMIC/SMMU route，不写存储。
错误有界停机且永久保留 DMA；没有自动重启控制器或拔插恢复。

启动参数：`k70_usb=1 k70_usb_wait_ms=60000 serial=3 debug=0x14e -enable_kprintf_spam`
（其他平台必需参数沿用经过核对的 ADT/loader 配置）。60 秒是一次有界前景
枚举窗口，允许 `0..60000` 毫秒；随后继续真实内核启动，并在
`clock_service_create` 后启动独立轮询线程。USB 中断不接 GIC，不依赖 IRQ 165。
每批最多消费 64 个事件；Bulk OUT 只接受有界 K70CTL/1 ASCII 请求。
单 slot mailbox 在 poll 内只做 framing/queue，命令仅在前景或独立线程的
poll 返回后执行。普通 console producer 不执行命令。协议规格在
`tools/xnu-debug/control-protocol.md`，支持 features/info/ping/status/uptime/
memory/bootargs/usb/replay；memory 仅返回归属元数据，不读任意地址。
未实现的阶段命令明确返回 unavailable。

软件重启需要当前非零 boot ID、reboot-arm 返回的十秒单次 token 与独立
reboot-confirm。仅从实际 FDT 验证后复制的 ADT `/psci` 接受 exact smc/hvc
method，经 PSCI_VERSION >=1.0 与 FEATURES(SYSTEM_RESET) 通过后才能启用。
不默认 conduit，不复制其他 SoC 的 PMIC 常量。ACK 一次原子追加，按真实
committed cursor 核验排空，失败即拒绝重启；停止并确认 USB HALTED 后才
执行标准 PSCI SYSTEM_RESET。系统级 reset 是否成功仍需下一次设备状态
证明，串口断开或返回 resetting 不代表已恢复 Android。
普通字符/console 日志生产者仅写环，不执行 USB 命令，避免在关中断的
kprintf/console 锁中等待硬件。仅明确的检查点、前景窗口和独立线程轮询。

证据边界：如果 XNU 停在 `arm_vm_init` 返回以前，USB 尚未初始化，本机环中
虽有先前检查点但电脑不能读取。前景窗口结束至轮询线程启动之间发生的
panic 也可能只留在内存环，尚无保证输出的独立 panic 泵。本版不声称能够覆盖最初汇编入口、MMU 前
异常或在下次启动自动提取旧内核环。固件 SEC 日志由独立保留区交接方案
负责；本版不会在 ExitBootServices 后执行任何 UEFI 代码或服务。

CI 集成：在新 checkout 的 device 上运行：

```text
python3 tools/xnu-debug/prepare_ci.py --device device --bundle sources/K70XnuDebug
```

修改 device 的补丁准备器，给本地补丁目录加入最后一个
`zzzz-k70-usb-log.patch`；在派生 tree 的构建脚本副本中把此补丁加入
late-patch reverse 列表最前，保证 bootstrap 和最终两次构建均可重复应用。
upstream checkout 与 source crypto 代码不动。
`source-manifest.json` 绑定所有新源码和 patch。构建前需额外保留 installer
报告，构建后验证真实 `_k70_xnu_early`、`_k70_xnu_after_vm`、
`_k70_xnu_thread_start` 符号及原有 source crypto POST/HMAC 报告。
