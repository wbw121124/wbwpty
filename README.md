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

## 5. 实施计划（阶段 / 提交序列）

| # | 阶段 | 内容 | commit |
| --- | --- | --- | --- |
| 0 | 骨架 | workspace / `.gitignore` / README / AGENTS / git 身份 | `chore: bootstrap cargo workspace for wbwpty` |
| 1 | 管道层 | 命名管道传输层（overlapped + pump） | `feat(pipe): named-pipe transport with overlapped io` |
| 2 | 子进程 | 挂起 + `DETACHED_PROCESS` 创建、环境块 | `feat(child): launch target suspended and detached without conhost` |
| 3 | 注入器 | PEB 遍历手工映射（PE 解析/重定位/导入/stub） | `feat(inject): manual-map injector via peb module walk` |
| 4 | DLL v1 | 开管道 + `SetStdHandle` + 可继承标记 | `feat(dll): redirect std handles to named pipes` |
| 5 | CLI | 会话循环：双泵 / EOF / 退出码 / Ctrl+C | `feat(cli): interactive session over redirected stdio` |
| 6 | PEB | 控制台语义补丁 + 偏移运行时自检 | `feat(dll): fake attached-console state in peb process parameters` |
| 7 | CRT | `_open_osfhandle`/`_dup2`/`setvbuf`/`_flushall` | `feat(dll): repair and line-buffer the ucrt stdio streams` |
| 8 | shim | 内联跳板 + console API shim + 键入翻译 + resize | `feat(dll): console api shim via kernelbase inline hooks` |
| 9 | 测试 | cmd/python/大输出/stderr/无 conhost/孙进程 | `test: add integration coverage and conhost assertions` |
| 10 | 文档 | README 定稿 + push | `docs: document architecture, build, usage and limitations` |

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