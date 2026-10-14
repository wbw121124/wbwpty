# wbwpty

**ConPTY-free Windows terminal core.** 在 Windows 原生环境下实现终端启动器/终端核心：
**不使用 ConPTY、不使用 winpty、不使用 conhost.exe、不依赖 WSL、不依赖 SSH。**

通过 **PEB 遍历手工映射注入 DLL + 自定义命名管道**，在目标 CLI 进程内部重定向标准 I/O，
实现无 `conhost.exe` 的终端交互。

---

## 1. 核心原理

### 1.1 什么决定了会不会出现 conhost.exe

`conhost.exe` 只在 **进程被分配 console session** 时被拉起。创建标志决定一切：

| 创建标志 | 是否分配 console session | 是否拉起 conhost.exe |
| --- | --- | --- |
| 默认（有父 console 时继承） | 继承父的 | 复用父的 |
| `CREATE_NEW_CONSOLE` | 新建 | **是** |
| `CREATE_NO_WINDOW` | 新建（无窗口的 console） | **是** |
| `DETACHED_PROCESS` | **不分配** | **否** |

> 来源：Microsoft Terminal 设计文档 `doc/specs/#7335 - Console Allocation Policy.md`
> （原文：`DETACHED_PROCESS: No console inheritance, no console host spawned for the new process.`
> / `CREATE_NO_WINDOW: ... new console host is spawned for the new process.`），
> 以及 Eryk Sun 在 StackOverflow 的说明与 CPython issue #85785。

因此本项目**必须**用 `DETACHED_PROCESS | CREATE_SUSPENDED` 创建目标进程。

### 1.2 `ConsoleHandle = 0x123` 这类补丁的真实价值

`PEB->ProcessParameters->ConsoleHandle` **不是**决定 "要不要 conhost" 的开关（那在创建时已定），
它的价值在**子孙进程**：

当我们的目标进程（`cmd.exe` / `python.exe`）再去 `CreateProcess` 时，base API 会检查
**父进程** 的 `ProcessParameters->ConsoleHandle`：

- 为空 → 认为"父进程没有 console" → 给子进程**新分配** console → **又冒出 conhost.exe**
- 非空 → 认为"父进程有 console" → 子进程**继承**（沿用父的 std handle）→ 不冒 conhost

所以把 `ConsoleHandle` 打成一个非空的哨兵值（`0x123`），可以让整棵进程树都不再分配 console。
这正是 winpty 之外的"零 conhost"方案所依赖的关键技巧，本项目在 `peb.rs` 中实现并带偏移自检。

### 1.3 注入时机

```
CreateProcessW(DETACHED_PROCESS | CREATE_SUSPENDED)
        │
        │  初始线程处于挂起状态：连 ntdll!LdrInitializeThunk 都还没执行
        ▼
CreateRemoteThread → stub（手工映射镜像 + 修 IAT + 调 DllMain）
        │
        ▼
ResumeThread  ──►  loader 初始化 ──► ucrtbase!__acrt_initialize_stdio
                                         └─ 从 GetStdHandle() 取到我们的管道句柄
```

因为 ucrtbase 是在**之后**才初始化的，所以目标程序的 `printf/fprintf` 会自然地写到管道上，
**无需**（且不应该）去动 CRT 的私有 `FILE` 结构。

### 1.4 手工映射（manual map）而不是 LoadLibrary

把 DLL `LoadLibrary` 进一个 *挂起* 进程，理论上有风险：该进程的 loader 状态与进程堆
可能尚未初始化。我们改用**手工映射**：

1. 宿主解析本地 DLL：`SizeOfImage` / `AddressOfEntryPoint` / `DIR_BASERELOC` / `DIR_IMPORT` / 导出表
2. `NtQueryInformationProcess(ProcessBasicInformation)` 取目标 PEB → 遍历
   `PEB->Ldr->InMemoryOrderModuleList` 收集已加载模块（`ntdll`/`kernel32`/`kernelbase`/`msvcrt`…）
3. 选基址（优先 `ImageBase`，冲突就近找空洞），本地应用基址重定位
4. `VirtualAllocEx` + `WriteProcessMemory` 写入整块镜像
5. 逐个导入：读远程模块导出表解析函数地址，生成 `(IAT_RVA, addr)` 补丁表
6. `CreateRemoteThread` 跑一段 ~40 条指令的 stub：填 IAT → 调 `DllMain(DLL_PROCESS_ATTACH)`

这样完全不依赖目标进程的 loader 状态，并且可以直接调用我们导出的 `DllMain`，
跳过 mingw CRT 的 `DllMainCRTStartup`（那个需要未初始化的 CRT 状态）。

### 1.5 Console API shim

`cmd.exe` / `python.exe` 在 std handle 是管道时本来就能工作（它们会退化成文件 I/O 路径）。
但很多程序**硬依赖控制台 API**（`GetConsoleMode` / `WriteConsoleW` / `GetConsoleScreenBufferInfo`）。
在目标进程内对 `KernelBase` 的同名导出做 x64 内联跳板（inline hook），
把这些 API 换成我们的实现，让目标"自认为是控制台"，而 I/O 实际走管道：

- `Get/SetConsoleMode` → 虚拟 mode（`ENABLE_VIRTUAL_TERMINAL_PROCESSING` 等）
- `WriteConsoleA/W` → UTF-16 → UTF-8 写输出管道
- `ReadConsoleA/W` / `ReadConsoleInputW` → 读输入管道 + 行编辑回显 + 合成按键事件
- `GetConsoleScreenBufferInfo(Ex)` → 返回宿主上报的窗口尺寸
- `AllocConsole`/`FreeConsole` → no-op，`AttachConsole` → 失败

> 实测依据：本机 `kernel32!GetConsoleMode` 等只是 6 字节 `jmp [rip+disp32]` 桩，
> 真实实现在 `KernelBase.dll`，因此只需 hook `KernelBase` 即可覆盖所有 kernel32 调用者。

---

## 2. 架构

```
 宿主 wbwpty.exe
 ├─ pipe.rs    : \\.\pipe\wbwpty-<pid>-<nonce>-{in,out,ctl}（server，FILE_FLAG_OVERLAPPED）
 ├─ child.rs   : CreateProcessW(DETACHED_PROCESS|CREATE_SUSPENDED, 自定义环境块)
 │               环境变量契约：WBWPTY_IN / WBWPTY_OUT / WBWPTY_CTL / WBWPTY_ROWS /
 │                            WBWPTY_COLS / WBWPTY_CP / WBWPTY_SHIM / WBWPTY_LOG
 ├─ inject.rs  : PEB 遍历 + 手工映射 + CreateRemoteThread
 └─ session.rs : 输出泵(stdout/stderr→本机) + 输入泵(本机 stdin→in 管道) + 退出码 + EOF
                              │
 ═════════════════════════════▼ 进程边界（无 conhost）
 wbwpty_redirect.dll（cdylib, no_std, panic=abort）
 ├─ DllMain（loader-safe，不碰堆/TLS）
 │    CreateFileW 打开管道 → SetStdHandle(0/1/2) → 标记可继承
 │    → PEB ConsoleHandle/ConsoleFlags 打桩 → CreateThread 起 worker
 └─ worker 线程
      CRT 修复（_open_osfhandle/_dup2/setvbuf(_IOLBF)/读前 _flushall）
      + [可选] KernelBase 内联 hook（console API shim）
      + ctl 管道轮询（窗口尺寸变化）
```

---

## 3. 项目结构

```
D:\wbwpty
├── Cargo.toml                  # cargo workspace
├── .gitignore
├── README.md                   # 本文件
├── AGENTS.md                   # 开发者/AI 协作注意事项
├── crates/
│   ├── wbwpty-core/            # lib：可嵌入的终端核心
│   │   └── src/
│   │       ├── lib.rs          # 公开 API：Session / SessionBuilder
│   │       ├── error.rs
│   │       ├── pipe.rs         # 命名管道传输层（overlapped + pump）
│   │       ├── child.rs        # 挂起 + DETACHED_PROCESS 创建、环境块
│   │       ├── inject.rs       # 注入入口（手工映射）
│   │       ├── manual_map/     # PE 解析 / PEB 遍历 / 重定位 / 导入 / stub
│   │       ├── session.rs      # 会话生命周期、双泵、退出码
│   │       ├── console.rs      # 宿主终端状态（rows/cols/codepage）
│   │       └── inspect.rs      # Toolhelp32 快照：conhost 校验
│   ├── wbwpty/                 # bin：CLI
│   │   ├── src/main.rs
│   │   └── tests/it_*.rs       # 集成测试
│   └── wbwpty-redirect/        # cdylib：注入 DLL（no_std）
│       └── src/
│           ├── lib.rs          # DllMain 入口 + 调度
│           ├── ffi.rs          # 手写 extern "system" 声明
│           ├── config.rs       # 环境变量契约解析
│           ├── log.rs          # OutputDebugStringA + 可选文件日志
│           ├── stdio.rs        # SetStdHandle + 继承标记
│           ├── peb.rs          # NtCurrentTeb→PEB 补丁 + 偏移自检
│           ├── crt.rs          # _open_osfhandle/_dup2/setvbuf/_flushall
│           ├── hook.rs         # x64 内联跳板（iced-x86 长度校验）
│           ├── console_api.rs  # 控制台 API 替身
│           └── keys.rs         # 字节流 ↔ 按键事件 / VT 翻译
```

---

## 4. 构建与运行

```powershell
# 构建（宿主 + 注入 DLL）
cargo build --release

# 运行
.\target\release\wbwpty.exe -- cmd.exe /c echo hello
.\target\release\wbwpty.exe -- python.exe -i
.\target\release\wbwpty.exe --dump-conhost -- cmd.exe /c echo hello   # 验证无 conhost

# 测试
cargo test --release
```

> 注入 DLL 默认从 `<exe 同目录>/wbwpty_redirect.dll` 加载，可用 `--dll <path>` 或
> 环境变量 `WBWPTY_DLL` 覆盖。

---

## 5. 实施计划与当前进度

| # | 阶段 | 内容 | commit | 状态 |
| --- | --- | --- | --- | --- |
| 0 | 骨架 | workspace / `.gitignore` / README / AGENTS / git 身份 | `chore: bootstrap cargo workspace for wbwpty` | ✅ |
| 1 | 管道层 | 命名管道传输层（overlapped + pump） | `feat(pipe): named-pipe transport with overlapped io` | ✅ |
| 2 | 子进程 | 挂起 + `DETACHED_PROCESS` 创建、环境块 | `feat(child): launch target suspended and detached without conhost` | ✅ |
| 3 | 注入器 | PE 解析 / 重定位 / 导出解析 / PEB 遍历 / 入口 trampoline | `feat(inject): manual-map injector via peb module walk` | 🟡 进行中 |
| 4 | DLL v1 | 开管道 + `SetStdHandle` + 可继承标记 | `feat(dll): redirect std handles to named pipes` | ⏳ |
| 5 | CLI | 会话循环：双泵 / EOF / 退出码 / Ctrl+C | `feat(cli): interactive session over redirected stdio` | ⏳ |
| 6 | PEB | 控制台语义补丁 + 偏移运行时自检 | `feat(dll): fake attached-console state in peb process parameters` | ⏳ |
| 7 | CRT | `_open_osfhandle`/`_dup2`/`setvbuf`/`_flushall` | `feat(dll): repair and line-buffer the ucrt stdio streams` | ⏳ |
| 8 | shim | 内联跳板 + console API shim + 键入翻译 + resize | `feat(dll): console api shim via kernelbase inline hooks` | ⏳ |
| 9 | 测试 | cmd/python/大输出/stderr/无 conhost/孙进程 | `test: add integration coverage and conhost assertions` | ⏳ |
| 10 | 文档 | README 定稿 + push | `docs: document architecture, build, usage and limitations` | ⏳ |

### 5.1 已完成部分的实际状态

- `cargo build` 绿；`cargo test --workspace` = **18 passed / 1 ignored / 0 failed**
- `wbwpty_redirect.dll` 可构建：`no_std` + `panic=abort` cdylib，导出 `DllMain`（RVA 见 objdump）
- 手工映射注入器的**每一段机器码都被执行验证过**（不是只比对字节）：
  入口 dispatcher 的"自旋 → 还原入口字节 → 调 DllMain → 跳回原入口"全流程有单测
- 唯一 ignored 的测试就是下面的阻塞点

### 5.2 关键技术发现（全部本机实测，恢复工作时不要推翻）

1. **只有 `DETACHED_PROCESS` 不拉 conhost**（微软 Terminal `doc/specs/#7335` 原文佐证）。
2. **挂起进程的 `PEB->Ldr` 是 NULL**：`CREATE_SUSPENDED` 时 loader 还没跑，
   目标进程里除 exe 自身和 ntdll 外**什么都没映射**。实测在宿主的
   `KERNEL32.dll` 基址读目标内存会 `ERROR_PARTIAL_COPY`。
   → "先注入 → 再从目标解析导入" 这条路走不通，必须让 loader 先跑起来。
   → 同时说明 `PEB->Ldr` 遍历在**运行中**的进程上是正常的（有单测覆盖）。
3. **注入时机方案（已实现）**：在挂起状态下把目标 exe 的入口改成
   `jmp dispatcher`（`E9 rel32`），然后 resume。loader 跑完、走到入口时
   dispatcher 自旋等宿主；宿主此刻 PEB 遍历可用，于是完成
   重定位 → 导入解析 → 写镜像 → 填 slot → 放行；dispatcher 还原入口字节、
   调 `DllMain`、再跳回真入口。
   **不用调试器、无竞态，且 `DllMain` 早于目标 CRT 初始化**（正是"重定向能在
   CRT 之前生效"所需要的）。
4. **x64 PE 的重定位类型是 `IMAGE_REL_BASED_DIR64`(10)，不是 `HIGHLOW`(3)**。
   最初只实现了 HIGHLOW，被"解析真实产物"的单测当场抓出来；现在两种都实现。
5. 本机 `ucrtbase.dll` 导出表实测：`setvbuf`/`_setmode`/`_open_osfhandle`/
   `_dup2`/`_flushall`/`__acrt_iob_func` 可用；
   `__acrt_lowio_set_osfhandle`/`_setvbuf` **未导出** → CRT 修复只能走公开 API。
6. `kernel32` 的控制台导出只是 **6 字节 `jmp [rip+disp32]` 桩**，真实实现在
   `KernelBase.dll` → console shim 只需 hook `KernelBase`。
7. 宿主工具链是 **MinGW gnu**（无 MSVC）。`no_std` cdylib 需要自己提供
   `rust_eh_personality`，因为 sysroot 里的 `core` 是按 unwind 编译的。

### 5.3 Stage-3 阻塞点的**根因**（已定位，方案已定）

`manual_map::tests::injects_into_a_suspended_cmd`（入口 trampoline 方案）失败，
`cmd.exe` 永不进入口点。把注入动作拆开逐个测（本机实测，`cmd.exe /c exit 0`，
单测 `suspended_entry_point_cannot_be_rewritten` 已把结论钉住）：

| 宿主对"挂起中的目标"做了什么 | 目标退出码 |
| --- | --- |
| 什么都不写 | `0` |
| 在映像旁分配 RWX 页 + 写 dispatcher 代码 | `0` |
| 在 `.text` 里任意位置（入口点 −64 KiB）写 8 字节再还原 | `0` |
| **在入口点写 `E9 rel32`** | **`0x103` = `STATUS_POSSIBLE_DEADLOCK`** |
| **在入口点写 `EB FE`（跳自己自旋）** | **`0x103`** |

结论：**只有"改写入口点字节"这一件事会杀死目标**，而且目标死在 loader 里、
根本没走到入口点（自旋的 `EB FE` 从未执行）。其它一切（写 `.text`、分配 RWX、
重定位、解析导入）都安全。`cmd.exe` 是 `GUARD_CF` 映像
（`DllCharacteristics = 0xc160`），入口点是 loader 初始化期间唯一不允许
被改写的区域。

→ **"挂起 → 改写入口点 → resume → dispatcher 自旋等宿主"这条路在 Windows 上是死的**，
README 旧版 5.3 的猜测（std handle 为 NULL / conhost 之类）全部排除。

### 5.4 新的注入时机（已定，开始实现）

放弃入口点 trampoline，改成"**loader 跑完再注入**"：

1. 目标 `CreateProcessW(DETACHED_PROCESS | CREATE_SUSPENDED)`，std handle 通过
   **`STARTF_USESTDHANDLES` + 可继承管道句柄**直接交给目标——这让重定向**完全不需要
   抢在目标 CRT 之前**（`ucrtbase!__acrt_initialize_stdio` 初始化时拿到的就是真管道，
   只是缓冲策略是全缓冲，这由 Stage 7 的 `setvbuf(_IOLBF)` 事后修）。
2. `ResumeThread`。宿主轮询目标的 `PEB->Ldr`，**一旦非 NULL 就说明 loader 已映射完导入**
   （`peb_walk_works_once_the_target_is_running` 已证该走法可行）。
3. 此时再走已验证的手工映射：重定位 → 从目标 PEB 解析导入 → 写整块镜像 →
   `CreateRemoteThread(base + DllMain)`。**不再需要自旋 dispatcher、不再需要改写
   任何目标代码**（stub 只需 `CreateRemoteThread` 天然提供的"调到入口"语义）。
4. DLL 负责剩下的语义补丁：`ConsoleHandle` 哨兵（让孙进程不再分配 console）、
   控制台 API shim、CRT 行缓冲。这些不依赖"早于 CRT 初始化"。

这样保住了项目目标（零 conhost、无 ConPTY/winpty/WSL/SSH），并且去掉了唯一
一个跨不过去的时序假设。`EntryTrap` / `build_entry_dispatcher` /
`build_entry_patch` 随本方案作废。

`wbw121124/wbwtty` 的 `feature/pty-win10-early` 分支含一个渲染模块：
<https://github.com/wbw121124/wbwtty/tree/feature/pty-win10-early>

恢复工作时**先评估能否直接复用它的渲染/虚拟屏层**，避免重复实现 VT 渲染、
光标管理、ANSI 解析等与注入无关的部分。

---

## 6. 关键设计决策（已在本机实测验证）

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| 注入 | PEB 遍历手工映射 | 不依赖 loader/进程堆初始化状态 |
| DLL 运行时 | `no_std` + 手写 FFI，`panic=abort` | worker 线程可能早于目标 CRT 初始化，不能碰堆/TLS |
| DLL 入口 | 手工映射时直接调用导出的 `DllMain` | 跳过 mingw CRT 初始化；DLL 仍可被 LoadLibrary 正常加载 |
| CRT 修复 | 公开导出 API（`_open_osfhandle`/`_dup2`/`setvbuf`/`_flushall`） | 实测 17763 的 `ucrtbase` **未导出** `__acrt_lowio_set_osfhandle` / `_setvbuf`，不能靠私有结构手术 |
| 内联 hook | 自写 x64 跳板 + `iced-x86` 长度校验 | 不引重型依赖 |
| 运行时 | 2 个泵线程 + overlapped，不用 tokio | 延迟更低、依赖更少 |
| hook 目标 | `KernelBase` 而非 `kernel32` | kernel32 的控制台导出只是 6 字节跳转桩 |

---

## 7. 限制

- 仅 x64（宿主、DLL、目标三者同为 x64）。
- 目标必须是 x64 PE；32 位目标需要单独编译一份 x86 DLL 并走 WoW64 管道重定向路径。
- 控制台 API shim 覆盖的是"常用子集"，不是完整的 conhost 重新实现；
  光标定位、滚动区域、鼠标选择等高级特性不保证。
- 非管理员权限可用（只注入自己创建的子进程），但无法调试/注入其它用户权限的进程。

---

## 8. License

MIT