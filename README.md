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

### 1.2 孙进程必须用 `DETACHED_PROCESS` + `STARTF_USESTDHANDLES` 创建

这一节原本声称：`PEB->ProcessParameters->ConsoleHandle` 为空 → base API 给孙进程
新分配 console → 冒出 `conhost.exe`；把它写成非空哨兵（`0x123`）就能让整棵进程树
都不再分配 console。

**本机实测推翻了这个说法**（Windows 10 19045，`cmd.exe`，x64），并找到了真正的开关。

孙进程现状：它**有自己的 console**，输出进了那个 console，永远不进我们的管道。
两条独立证据：

- 进程树：`wbwpty → cmd → cmd → conhost.exe`
- 孙进程自己的 `mode con` 报告 `行数 9001 / 列数 120`（conhost 默认缓冲），
  而顶层目标的 `mode con` 什么都没有

试过并**全部无效**的干预：

| 干预 | 结果 |
| --- | --- |
| 目标启动前把 `ConsoleHandle` 写成 `0x123` | **目标直接死**：`STATUS_DLL_INIT_FAILED (0xC0000142)` |
| 目标启动前把它写成自己的 `StandardOutput`（真实句柄） | 同样 `0xC0000142` |
| 注入后写 `0x123` | 写进去了，能稳住整个会话 |
| 注入后**每 5ms 连续重申** `0x123` 两秒 | 孙进程**仍然**拿到 9001×120 的 console |
| `ConsoleFlags \|= STARTF_USESTDHANDLES`（0x100） | 无任何可观测差异，故未写入活进程 |

内核给 `DETACHED_PROCESS` + `STARTF_USESTDHANDLES` 创建的子进程
`ConsoleHandle = INVALID_HANDLE_VALUE`、`ConsoleFlags = 0x1`；
目标会在自己启动过程中（约 100 ms）把 `ConsoleHandle` 归一化成 `0`。

#### 真正有效的组合（实测矩阵）

`crates/wbwpty-core/tests/descendant_creation.rs` 用 `wbwpty-spawn-probe`
把 `CreateProcessW` 的创建标志 × `STARTF_USESTDHANDLES` 全跑了一遍：

| 创建方式 | 会冒 conhost | 输出进管道 |
| --- | --- | --- |
| 纯句柄继承 | 是 | 否 |
| 纯句柄继承（不继承句柄） | 是 | 否 |
| `STARTF_USESTDHANDLES` | 是 | **是** |
| `STARTF_USESTDHANDLES`（不继承句柄） | 是 | 否 |
| `DETACHED_PROCESS` | **否** | 否 |
| **`DETACHED_PROCESS` + `STARTF_USESTDHANDLES`** | **否** | **是** |
| `DETACHED_PROCESS`（不继承句柄） | 否 | 否 |
| `CREATE_NO_WINDOW` | 是 | 否 |
| `CREATE_NO_WINDOW` + `STARTF_USESTDHANDLES` | 是 | **是** |
| `CREATE_NEW_CONSOLE` | 是 | 否 |

**两半是独立的，只有一行同时满足两个承诺：**

- `STARTF_USESTDHANDLES` 负责**输出**——光靠句柄继承不行，这正是孙进程输出丢失的原因。
- `DETACHED_PROCESS` 负责**不冒 conhost**——光有显式标准句柄**不够**，
  这就是为什么 `cmd /c "cmd /c echo hi > file"`（重定向走的就是 `STARTF_USESTDHANDLES`）
  照样会弹出 conhost。

**因此 Stage 8 的方案已经确定**：在目标进程内拦截 `CreateProcess*`，同时做两件事——
把 `DETACHED_PROCESS` 或进 `dwCreationFlags`，并用父进程的 std handle 填
`STARTF_USESTDHANDLES`。只做其中一件，另一半承诺就是破的。

回归测试见 `tests/descendant_creation.rs`
（`detached_process_with_std_handles_is_what_a_descendant_needs` 断言的就是这一行），
以及 `session.rs` 里被 `#[ignore]` 的 `grandchild_output_reaches_the_pipe`——
它要等 hook 落地才能转绿。

#### 顺带测到的坑

`GetStdHandle(0..2)` 在某些进程里返回 `INVALID_HANDLE_VALUE`，尽管该进程的 stdout
是一个完全可用的管道。往子进程传这三个值等于传三个坏句柄，子进程立刻 exit 1。
要拿"本进程真正在写的句柄"，用 CRT 的 `as_raw_handle`，不要用 `GetStdHandle`。

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
在目标进程内把这些 API 的**导入槽**改写成指向 payload，让目标"自认为是控制台"，而 I/O 实际走管道。

**已实现（第一批，全部不依赖宿主）**：

| API | 实现 |
| --- | --- |
| `WriteConsoleW` | UTF-16 → UTF-8，写到会话的 stdout（分块过栈缓冲，DLL 无分配器） |
| `WriteConsoleA` | 原样字节写出（目标自己的编码就是终端要看到的东西） |
| `GetConsoleMode` / `SetConsoleMode` | 虚拟 mode word，默认带 `ENABLE_VIRTUAL_TERMINAL_PROCESSING` |
| `AllocConsole` / `FreeConsole` | no-op 且**返回成功**（真分配就会冒出 conhost） |
| `AttachConsole` | 恒定失败（没有 console 可附着） |

**尚未实现（需要屏幕）**：`GetConsoleScreenBufferInfo(Ex)` 这一族要光标位置和单元格网格，
而网格需要堆——注入 DLL 是 `no_std` 无分配器（AGENTS 规则 3），**虚拟屏不能放在 DLL 里**，
它在宿主那边（§5.6 的 `vt-parser`）。要回答这些调用就得往返宿主。
在做完之前这些函数**故意不被拦截**：放着不管会诚实地失败，
而用编出来的光标位置去应答会失败得莫名其妙。

> 实测依据：`kernel32` 的控制台导出只是 6 字节跳转桩，真实实现在 `KernelBase.dll`；
> 但**不需要**内联跳板——改写目标的**导入槽**就够了，而导入槽是数据，CFG 看不见它。
> 覆盖面限制同 `CreateProcessW`：**运行时用 `GetProcAddress` 取的 API 没有槽，不会被拦截**。

---

### 1.6 stdio 缓冲：`_IOLBF` 在管道上没用，要用 `_IONBF`

一个 CRT 对管道默认是**全缓冲**：实测（`tests/crt_buffering.rs`）写一行带换行的内容，
**701ms 后（进程退出时）才到达管道**。在终端里这就是"程序卡住了"。

原计划是 `setvbuf(_IOLBF)`。**实测不成立**。把候选值全扫一遍（UCRT）：

| 值 | ucrtbase 的实际行为 |
| --- | --- |
| `0` | `_IOFBF`，全缓冲，退出时才到 |
| `1`,`2`,`3`,`8`,`32`,`128` | 不是合法 mode → 跑非法参数处理器 → **进程 abort** |
| **`4`** | **`_IONBF`，1ms 就到** ✅ |
| `64` (`0x40`) | `_IOLBF`，但**对管道的行为和 `_IOFBF` 一模一样** |

所以：合法值就是 `0 / 4 / 0x40` 这三个，而 `_IOLBF` 对非 console 流不生效。
**`_IONBF`（4）才是能用的那个**——代价是每次写一次系统调用，对终端来说本来也是想要的行为。

> ⚠️ 这三个值是 **UCRT** 的，不是 mingw 的（mingw 是 `_IOFBF 0, _IOLBF 1, _IONBF 2`）。
> 所以是**实测出来的，不是查头文件**。别"修正"回头文件里的值。

另外两件事：

- `setvbuf` 必须在该流发生第一次 I/O **之前**调用才有意义（C 标准规定之后调用是未定义行为）。
  payload 最早只能在 loader 跑完后映射，那时目标的 CRT 早就初始化完了。
  实测这个时机**够用**——探针在 payload 到达后写的内容 0ms 就到了管道（对照组 702ms）。
- `_open_osfhandle` / `_dup2` **不需要**：标准描述符本来就是会话管道，
  宿主在目标跑第一条指令前就通过 `STARTF_USESTDHANDLES` 交出去了。

### 1.7 每一代都要被接管（supervisor）

IAT 替换只改**一个进程**的导入表：会话目标。这足够让**目标自己创建的**子进程正确
（`DETACHED_PROCESS` + 我们的句柄，无 conhost，输出进管道，由
`session::tests::grandchild_output_reaches_the_pipe` 钉住），但**不够**再往下。

导入表属于它被加载的那个映像。后代有自己的导入表，而**里面什么都没有**。
于是后代创建的进程用的是**后代自己选的**标志位——而一个没有 console 的 CUI 父进程
创建的 CUI 子进程会被 base API **分配一个 console**，那就是每个孙进程一个 `conhost.exe`。

办法是结构性的，不是技巧性的：**给每个后代同样的替换**。一个能替换自己
`CreateProcessW` 的进程，创建出来的子进程就是对的，于是这个性质沿整棵树归纳下去。

`crates/wbwpty-core/src/supervisor.rs` 做这件事：每 15ms 拍一次进程表，
对每个新出现的 pid `OpenProcess` → 映射 payload → 改写它的 IAT 槽 → 写 console 哨兵。

**为什么放在宿主侧而不是 payload 侧**：宿主已经有整套注入器，而 payload 自注入意味着
在一个不许碰堆的 `no_std` DLL 里重写一遍（映像映射 / 重定位 / 对子进程 loader 状态解析导入 / 远程线程）。
宿主也已经能碰到后代——树里所有进程都是同一个用户，
`tests/descendant_conhost.rs` 早就在从宿主往后代写哨兵了。

三件**不是可选项**的事：

1. **整个处理过程持有句柄**。pid 单独存在时，进程一退出它就被复用；
   往继承了那个 pid 的无辜进程里写 payload 是这里能犯的最严重的 bug。
2. **非 x64 的后代直接放弃，不尝试**。`remote.rs` 里每个偏移都是 x64 的，
   把 x64 映像写进 WOW64 地址空间不是"降级"，是**破坏**。
3. **loader 等待只有 150ms**（不是会话目标的 10s），失败就下一轮重试。
   后代往往只活几毫秒，为它阻塞十秒会把后面所有后代一起堵死。

覆盖记录是**边做边发**的，不是结束时才给：`Session::coverage()` 能区分
"在它来得及 spawn 之前就被接管"和"接管了但已经晚了"——这两者在输出上完全一样。

#### 为什么"挂起子进程直到被接管"这条路走不通（2026-10-16 实测）

最直接的修法当然是：让子进程以 `CREATE_SUSPENDED` 出生，宿主接管完再 resume。
**这条路与本项目的注入器根本不兼容**，有两个各自独立的阻塞点：

1. **挂起进程的 loader 从没跑过**。注入要先 `stable_modules()` 等
   `PEB->Ldr` 可遍历，而 `CREATE_SUSPENDED` 出来的进程里 `PEB->Ldr` 是 NULL
   （AGENTS 坑 7）。等多久都不会就绪。
   （`RemoteModules::discover` 的 `HostShared` 回退本来是为这种情况准备的，
   能拿到模块地址——但它只能解决第 1 条。）
2. **调 `DllMain` 的那个远程线程在挂起进程里不运行**。`inject_bytes` 最后一步是
   `CreateRemoteThread(base + DllMain)` 然后 `WaitForSingleObject(INFINITE)`；
   进程是挂起的，这个线程永远不返回，`run_thread` 于是**永久阻塞**。
   实测表现：监督线程挂死 → `Drop for Session` 里 join 它 → **整个测试挂住**
   （实测一次 `cargo test` 超过 300 秒未结束，并留下孤儿 `cmd.exe`）。

所以唯一可行的变体是**把注入拆成两段**：挂起期间只做"映射 + 解析导入 + 改 IAT"
（全是数据写入，对挂起进程合法），**resume 之后再补那一次 `CreateRemoteThread`**。
这需要把 `inject_bytes` 拆成 map / call-entry 两步，并让监督线程知道
"映像已就位、入口待调用"。这是一个独立的、有分量的改动，不该顺手做。

在那之前，§1.7 末尾那个竞态**是已知的、未关闭的**：supervisor 是轮询的，
一个在自己起来几毫秒内就 spawn 的后代可以跑赢这一轮。
`Coverage` 记录的就是这件事，不藏。

### 1.8 故意制造 console host 的测试一律 `#[ignore]`

`cargo test` 默认会跑 46 条测试，其中 **9 条被 ignore**，全部是同一个理由：
它们**按设计会在操作者桌面上弹出真实的 conhost 窗口**——
而那正是本项目要阻止的东西，没有它就没法观察。

跑它们必须显式指定，例如：

```powershell
cargo test --release --test descendant_injection -- --ignored without_the_supervisor
```

**默认不跑，不要顺手跑。** 唯一例外是 `tests/descendant_injection.rs` 里那两条：
它们在设计上就不该产生任何 console host（第三代测试还有一道运行时安全闸，
见该文件），所以它们是普通测试。

## 2. 架构

```
 宿主 wbwpty.exe
 ├─ pipe.rs    : \\.\pipe\wbwpty-<pid>-<nonce>-{in,out,ctl}（server，FILE_FLAG_OVERLAPPED）
 ├─ child.rs   : CreateProcessW(DETACHED_PROCESS|CREATE_SUSPENDED, 自定义环境块)
 │               环境变量契约：WBWPTY_IN / WBWPTY_OUT / WBWPTY_CTL / WBWPTY_ROWS /
 │                            WBWPTY_COLS / WBWPTY_CP / WBWPTY_SHIM / WBWPTY_LOG
 ├─ manual_map/: PEB 遍历 + 手工映射 + CreateRemoteThread + IAT 改写
 ├─ supervisor.rs: 轮询进程表，把上面那套铺到每一个后代（§1.7）
 └─ session.rs : 输出泵(stdout/stderr→本机) + 输入泵(本机 stdin→in 管道) + 退出码 + EOF
                              │
 ═════════════════════════════▼ 进程边界（无 conhost）
 wbwpty_redirect.dll（cdylib, no_std, panic=abort）
 ├─ DllMain（loader-safe，不碰堆/TLS）
 │    CreateFileW 打开管道 → SetStdHandle(0/1/2) → 标记可继承
 │    → PEB ConsoleHandle/ConsoleFlags 打桩 → CreateThread 起 worker
 └─ worker 线程
      CRT 修复（setvbuf(_IONBF)，见 §1.6）
      + create_process_w()：替身（§1.2 / §1.7）
      + [未实现] console API 替身
      + ctl 管道轮询（窗口尺寸变化）
```

> **每一个被接管的进程里都有这份 DLL**——目标，以及每一个后代（§1.7）。
> 正是这一点让"创建子进程时不冒 conhost"这个性质能沿整棵树归纳下去。

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
│   │   ├── src/
│   │   │   ├── lib.rs          # 模块表 + 公开 API：Session / SessionConfig
│   │   │   ├── error.rs
│   │   │   ├── pipe.rs         # 命名管道传输层（overlapped + pump）
│   │   │   ├── child.rs        # 挂起 + DETACHED_PROCESS 创建、环境块契约
│   │   │   ├── manual_map/     # PE 解析 / PEB 遍历 / 重定位 / 导入 / stub / IAT / hook
│   │   │   ├── supervisor.rs   # 进程树监督：把注入铺到每一个后代（§1.7）
│   │   │   ├── session.rs      # 会话生命周期、双泵、退出码、supervisor 接线
│   │   │   ├── inspect.rs      # Toolhelp32 快照 + ancestry 归因
│   │   │   └── bin/            # 测试夹具：wbwpty-spawn-probe / wbwpty-crt-probe
│   │   └── tests/              # 集成测试（见 §1.8 哪些不能默认跑）
│   ├── wbwpty/                 # bin：CLI
│   │   └── src/main.rs
│   ├── wbwpty-redirect/        # cdylib：注入 DLL（no_std）
│   │   └── src/
│   │       ├── lib.rs          # DllMain 入口 + worker 调度 + 发布的状态字
│   │       ├── ffi.rs          # 手写 extern "system" 声明
│   │       ├── config.rs       # 环境变量契约解析
│   │       ├── log.rs          # OutputDebugStringA + 可选文件日志
│   │       ├── stdio.rs        # SetStdHandle + 继承标记
│   │       ├── peb.rs          # NtCurrentTeb→PEB 补丁 + 偏移自检
│   │       ├── crt.rs          # setvbuf(_IONBF)（见 §1.6）
│   │       ├── hook.rs         # create_process_w 替身（§1.2/§1.7）
│   │       └── console.rs      # 控制台 API 替身：不需要屏幕的那一批（§1.5）
│   ├── vt-parser/              # vendor 自 wbwtty：VT 解析 + 虚拟屏（零平台依赖）
│   └── term-input/             # vendor 自 wbwtty：按键/鼠标 → VT 字节
```

> 尚未实现：**需要屏幕的那一族**控制台 API（`GetConsoleScreenBufferInfo` 等，见 §1.5）
> ——设计由 §5.6 的复用结论给出（屏幕在宿主侧，payload 只能往返问）。
> `keys.rs` 的职责已由 vendor 进来的 `term-input` 覆盖。

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
| 3 | 注入器 | PE 解析 / 重定位 / 导出解析 / PEB 遍历；**loader 跑完再注入**，废弃入口 trampoline | `feat(inject): map the payload once the target loader has finished` | ✅ |
| 4 | stdio | **`STARTF_USESTDHANDLES` + 可继承管道句柄**，重定向不再依赖 DLL 注入时机 | `feat(session): run a target over pipes with no console host` | ✅ |
| 5 | CLI | 会话循环：双泵 / EOF / 退出码 / `--dump-conhost` / `--verbose` | （同上） | ✅ |
| 6 | PEB | 宿主侧（挂起态 + 注入后各一次）读/写目标 `ConsoleHandle`，偏移断言 + 运行时自检；**实测无法阻止孙进程分配 console**，见 §1.2 | `fix(peb): own the console state from the host side` | ✅（机制被证伪，已记录） |
| 7 | CRT | `config.rs` 环境契约 + 接上 `log::init_from_env` + worker 线程 + `setvbuf(_IONBF)`（**不是 `_IOLBF`**，见 §1.6） | `feat(dll): unbuffer the target stdio streams so output is not held back` | ✅ |
| 8 | shim | `CreateProcess*` 的 IAT 拦截 + **supervisor 把替换铺到每一个后代**（见 §1.7）；console API 替身**第一批**（`WriteConsoleW`/`GetConsoleMode` 等，见 §1.5），需要屏幕的那一族未做 | `feat: cover every generation of the process tree with a descendant supervisor`<br>`feat: substitute the console APIs that need no screen` | ✅（部分） |
| 9 | 测试 | cmd/python/大输出/stderr/无 conhost/孙进程 | ⏳ |
| 10 | 文档 | README 定稿 | ⏳ |

### 5.1 已完成部分的实际状态（截至本次提交）

- `cargo build --release` 绿；`cargo test --release` = **138 passed / 0 failed / 9 ignored**
  （其中 **88 条来自 vendor 进来的 `vt-parser` / `term-input`**，它们自带的测试在本机全绿；
  9 条 ignored 的是**故意制造 console host** 的对照组，默认不跑，见 §1.8）。
- `wbwpty.exe --dump-conhost -- cmd.exe /c echo hello` 实测：**hello 原样输出，exit=0，conhost.exe 数量不变**。
- **三代进程树实测无 console host**（`probe → probe → ping`）：第三代的 `DETACHED_PROCESS`
  是从**后代自己 payload 里发布的 `WBWPTY_HOOK_FLAGS`** 读出来的，不是"碰巧没弹窗"。
  见 §1.7 与 `tests/descendant_injection.rs`。
- `--shim` **现在是真的了**（第一批）：`WriteConsoleW` / `WriteConsoleA` / `GetConsoleMode` /
  `SetConsoleMode` / `AllocConsole` / `FreeConsole` / `AttachConsole` 的导入槽被改写，
  实测 `WriteConsoleW` 的输出真的进了管道，而关掉 shim 同一个调用什么也不产生
  （`tests/console_shim.rs`，正反两条都断言）。
  **仍未实现**：需要屏幕的那一族（`GetConsoleScreenBufferInfo` 等），见 §1.5。
- 手工映射每一段机器码都有**真正执行**的单测（不是只比对字节），`stub.rs` 已简化为只负责"调 DllMain"，不再携带死代码。
- 核心注入失败根因已定位：**stub 用 `r9d` 而不是 `edx` 传 `DLL_PROCESS_ATTACH`**（Win64 第 2 参数在 `rdx`），导致 `DllMain` 拿到假 reason 直接 return TRUE 而不做任何事；修完后 stub 调用真实成功。
- **Stage 7 完成并实测有效**：同样的探针、同样的管道、同样的写，
  无 payload 时输出 702ms 才到，有 payload 时 **0ms**（`tests/crt_buffering.rs`）。
  `WBWPTY_LOG` 也第一次真正生效——之前 `log::init_from_env()` 从来没被调用过。
- `cmd /c <短命令>` 这类目标**基本永远注不进去**：`stable_modules` 需要 ~100ms 稳定窗口，
  而目标几毫秒就退出。stdio 走 `STARTF_USESTDHANDLES` 所以不影响它工作，但任何注入侧的
  语义补丁（哨兵、shim、CRT）对它都不生效。**这也包括 Stage 7 的缓冲修复。**
  → 更要命的是：这种目标如果在自己起来的前几毫秒里就 spawn 子进程，
  那时连 supervisor 都还没覆盖到它，**子进程会拿到自己的 console**（§1.7 末尾）。

### 5.2 关键技术发现（全部本机实测，恢复工作时不要推翻）

1. **只有 `DETACHED_PROCESS` 不拉 conhost**（微软 Terminal `doc/specs/#7335` 原文佐证）。
2. **挂起进程的 `PEB->Ldr` 是 NULL**：`CREATE_SUSPENDED` 时 loader 还没跑，
   目标进程里除 exe 自身和 ntdll 外**什么都没映射**。实测在宿主的
   `KERNEL32.dll` 基址读目标内存会 `ERROR_PARTIAL_COPY`。
   → "先注入 → 再从目标解析导入" 这条路走不通，必须让 loader 先跑起来。
3. **entry-point trampoline 对 `GUARD_CF` 映像致命**：`cmd.exe`（`DllCharacteristics=0xc160`）在入口点写 `E9 rel32` 后 resume，loader 立即以 `STATUS_POSSIBLE_DEADLOCK (0x103)` 杀死进程，根本走不到入口点；同进程的任意 `.text` 位置写入再还原则完全无害。**结论：放弃入口点 trampoline，改走"loader 跑完再注入"**。
4. **模块列表就绪信号必须是"稳定快照"而非"非空"**：`LdrpInitializeProcess` 先发布 `PEB->Ldr` 再逐个链接模块，短窗口内列表为空或不完整；以 50ms 稳定间隔对比两次快照来判断就绪，才不会再踩 `walk produced nothing` 或 `not doubly linked`。
5. **`WriteProcessMemory` 要求目标页已提交**：`VirtualQueryEx` 报告 `MEM_FREE` 不代表可写，必须用 `VirtualAllocEx` 真正预留+提交；旧代码只探测不提交，导致 `ERROR_INVALID_ADDRESS (998)`。
6. **x64 import thunk 步进是 8 不是 16**：`IMAGE_THUNK_DATA64` 就是一个 `u64`，旧代码按 32-bit PE 步进 16 字节，读取的 RVA 全是垃圾（表现为 `"string at 0x65e0ac22 is outside the image"`）。
7. **`api-ms-win-crt-*` DLL 不是真实磁盘文件**：`GetModuleHandleW` 在宿主里能拿到基址，但那个基址在目标里未映射；必须以目标 PEB 快照为准。
8. **`STARTF_USESTDHANDLES` + 可继承句柄**是让 stdio 在 CRT 初始化之前接管的标准做法；宿主必须立刻释放自己持有的客户端副本，否则 `-out` 管道的 writer 永远不为空 → 死等 EOF。
9. **stub 传参：Win64 ABI 第 2 参数在 `rdx`，不是 `r9`**。`mov r9d, 1` 编译无错但 `DllMain` 拿到的 `fdwReason` 是残留垃圾值，整条 attach 路径静默跳过；必须用 `mov edx, 1`。
10. **宿主工具链是 MinGW gnu（无 MSVC）**。`no_std` cdylib 需要自己导出 `rust_eh_personality`。
11. **目标启动完成前不能碰 `ConsoleHandle`**，见 §1.2 与 AGENTS 坑 12。
12. **`ConsoleHandle` 哨兵挡不住孙进程**，见 §1.2 与 AGENTS 坑 13。

### 5.3 当前状态（截至本次提交）

`DllMain` 已能正常跑通，且 `WBWPTY_STATUS` 现在会回报它走到了哪一步
（低 16 位 = 阶段，高 16 位 = `fdwReason`），`wbwpty.exe --verbose` 会打印
目标的 `ConsoleHandle` / `ConsoleFlags` / `StandardOutput` 以及注入结果。
`--verbose` 输出示例：

```text
wbwpty: pid 4328 console_handle=0x123 console_flags=0x1 standard_output=0xcc
wbwpty: pid 4328 sentinel Written(ConsoleState { console_handle: 291, console_flags: 1, standard_output: 204 })
wbwpty: pid 4328 payload stage=ConsoleAlreadySet reason=1 attach_path_ran=true
```

**孙进程问题已经修好了两代，第三代靠 supervisor（§1.7）。** 下一步：

- **关掉 supervisor 的轮询竞态**：子进程以 `CREATE_SUSPENDED` 创建 → pid 日志 →
  宿主注入完再 resume。这是唯一能把 §1.7 末尾那个"几毫秒内 spawn 就能跑赢"消掉的做法。
- **实现 console API shim**（§1.5）。`--shim` 现在是空承诺。
- Stage 9：端到端测试（python、大输出、stderr）。
- Stage 10：README 定稿。

### 5.4 Stage-3 阻塞点的**根因**（已定位，方案已定）

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

### 5.5 新的注入时机（**已实现**）

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
4. DLL 负责剩下的语义补丁：控制台 API shim、CRT 行缓冲。这些不依赖"早于 CRT 初始化"。
   （`ConsoleHandle` 哨兵原本也在这条路上，但 §1.2 实测它对孙进程无效。）

这样保住了项目目标（零 conhost、无 ConPTY/winpty/WSL/SSH），并且去掉了唯一
一个跨不过去的时序假设。`EntryTrap` / `build_entry_dispatcher` /
`build_entry_patch` 随本方案作废。

`wbw121124/wbwtty` 的 `feature/pty-win10-early` 分支含一个渲染模块：
<https://github.com/wbw121124/wbwtty/tree/feature/pty-win10-early>

恢复工作时**先评估能否直接复用它的渲染/虚拟屏层**，避免重复实现 VT 渲染、
光标管理、ANSI 解析等与注入无关的部分。

### 5.6 复用评估结论（2026-10-16 实测）

**结论：`vt-parser` + `term-input` 值得 vendor 进来，其余不要。**

| wbwtty 的 crate | 决定 | 理由 |
| --- | --- | --- |
| `crates/vt-parser` | **vendor 复用** | 纯 Rust、**零平台依赖**、自带 19 条单测（覆盖 UTF-8 跨 `feed` 切分、宽字符、备用屏、滚动区、SGR truecolor、DA/DSR 应答） |
| `crates/term-input` | **vendor 复用** | 键→VT 编码，正好配 `vt-parser` 的模式查询 |
| `crates/term-render-gtk` | **不要** | GTK/pango，与本项目的宿主形态无关 |
| `crates/pty-win10-early` | **不要** | 含 `csrc/conhook.c`，需要 `cc` 构建——AGENTS 规则 2 明令禁止 |

`vt-parser` 的公开 API 与本项目需要的几乎一一对应：

```rust
Terminal::new(cols, rows) / with_options(scrollback_limit)
feed(&[u8])            // 增量，UTF-8 与序列状态跨调用保持
get_screen() -> ScreenView   // 单元格网格 + damage 行 + 光标
take_replies() -> Vec<u8>    // DA/DSR 应答 → 写回子进程 stdin
resize(cols, rows)     // 窗口尺寸变化
application_cursor_keys() / bracketed_paste() / mouse_mode() / is_alt_screen()
```

**这直接决定了 console API shim（Stage 8 剩下的部分）该怎么写**：
`WriteConsoleA/W` 把 UTF-16 转 UTF-8 喂进 `Terminal`、顺带写输出管道；
`GetConsoleScreenBufferInfo` 读它的光标与几何；`GetConsoleMode` 读模式位；
DA/DSR 的应答走 `take_replies()` 灌进 `-in` 管道。自己重写这一套是几百行
且必然漏边界情况，而这份是测过的。

**两个必须先解决的前置条件：**

1. **wbwtty 没有任何 license 声明**——仓库根目录无 `LICENSE`，workspace 与各 crate
   都没有 `license` 字段，且全部 `publish = false`。两边仓库都是 `wbw121124` 的，
   实际归属清楚，但**把代码抄进 MIT 的 wbwpty 之前应先补一份明确的 license 声明**，
   否则 "MIT" 这个说法没有依据。
2. 全部 crate 都是 `path` 依赖 + `publish = false`，所以只能**vendor 源码目录**，
   不能按 git 依赖引入。

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
