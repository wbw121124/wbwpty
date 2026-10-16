# AGENTS.md — wbwpty 协作注意事项

本文件是给**人类开发者与 AI 编码代理**共同遵守的工程约束。
动手前请完整读一遍，改完请对照"提交纪律"和"验收要求"自查。

---

## 0. 项目一句话

Windows 原生终端核心：**不用 ConPTY / winpty / conhost / WSL / SSH**，
靠 **PEB 遍历手工映射注入 DLL + 命名管道** 重定向目标进程的标准 I/O。

## 1. 绝对红线

1. **禁止引入 ConPTY / winpty / WSL / SSH**。相关 API 名称（`CreatePseudoConsole`、
   `HPCON`、`ResizePseudoConsole`、`winpty`、`WSL`、`ssh`）不得出现在代码里。
   出现即视为违背项目目标。
2. **禁止 `CREATE_NO_WINDOW` / `CREATE_NEW_CONSOLE`**，它们**仍然会拉起 conhost.exe**。
   创建目标进程只能用 `DETACHED_PROCESS | CREATE_SUSPENDED`。
3. **禁止在注入 DLL 里使用 `std`**（`crates/wbwpty-redirect` 必须是 `#![no_std]`）：
   - 不许用 `String` / `Vec` / `format!` / `Box` / `std::thread` / 任何全局分配器。
   - 固定容量用栈数组（`[u8; 256]` 等），格式化用 `core::fmt::Write` 写进栈缓冲。
   - 原因：worker 线程可能早于目标进程的 CRT/堆初始化完成，碰堆 = 随机崩溃。
4. **禁止硬编码未经验证的 PEB/PEB_LDR 偏移**。所有偏移必须
   (a) 集中在结构体定义里并写明来源，(b) 提供运行时自检函数（如 `self_test()`），
   (c) 在结构体顶部 `const _: () = assert!(offset_of!(...) == 0x20)` 断言。
   若自检失败，**降级而不是崩溃**（跳过补丁并记录诊断）。
5. **禁止瞎编 Win32 结构/偏移/API**。不确定就去查：
   - 本机二进制：`(dumpbin 不可用时) "C:\Program Files\mingw64\bin\objdump.exe" -p <dll>` 看导出表
   - 头文件：`C:\Program Files (x86)\Windows Kits\10\Include\<ver>\um\<api-set>.h`
   - 官方文档 / ReactOS / Microsoft Terminal 设计文档 / CPython / dotnet/runtime 源码
6. **禁止提交编译不过或测试失败的代码**。每个阶段结束必须 `cargo build`（+ 相关 `cargo test`）是绿的。

## 2. 技术栈约束

- 工具链：`x86_64-pc-windows-gnu`（Rust 1.99，MinGW gcc）。**本机没有 MSVC，不要引入
  `cc` 编译的 C 代码**。
- 宿主与 DLL 都用 `windows-sys`（原始 FFI，签名与 Win32 一一对应）。
  不要用 `windows`（safe wrapper），因为我们要精确控制 `BOOL` 返回值与 `last_os_error`。
- 异步运行时：**不用 tokio**。会话模型是两个泵线程 + `FILE_FLAG_OVERLAPPED`。

## 3. 环境变量契约（宿主 → 注入 DLL）

宿主为子进程构造环境块，追加下列变量；DLL 在 `DllMain` 里读取。

| 变量 | 含义 |
| --- | --- |
| `WBWPTY_IN` | 输入管道名（宿主 → 目标） |
| `WBWPTY_OUT` | 输出管道名（目标 → 宿主） |
| `WBWPTY_CTL` | 控制管道名（resize 等双向控制，可选） |
| `WBWPTY_ROWS` / `WBWPTY_COLS` | 虚拟终端尺寸 |
| `WBWPTY_CP` | 目标控制台代码页（0 = 不覆盖） |
| `WBWPTY_SHIM` | `1` = 安装 console API shim，`0` = 不装 |
| `WBWPTY_LOG` | DLL 日志文件路径（可选，栈缓冲写） |

**契约一旦发布就不能改名**：改名会让已发布的注入 DLL 与新宿主静默失配。

## 4. 模块职责边界

- `wbwpty-core/manual_map/`：**只**负责"把一个 PE 映进远程进程并调用它的入口"。
  不许在这里掺入终端语义。
- `wbwpty-core/pipe.rs`：只管字节传输，不管编码/转义。
- `wbwpty-redirect/`：只管目标进程内部的重定向与补丁，不许调用宿主 API。
- `wbwpty/`（bin）：CLI + 编排，保持薄。

## 5. 错误处理与日志

- 宿主：统一 `anyhow`，所有 Win32 调用失败必须带上下文
  （`.with_context(|| format!("CreateFileW({name})"))`），并附 `last_os_error`。
- DLL：无法返回错误，用 `log.rs` 的 `dlog!` 输出到 `OutputDebugStringA`
  （+ 可选文件）。**任何补丁失败都要能降级，不许让目标进程崩**。
- 宿主默认把 DLL 日志转发到 `WBWPTY_LOG` 指定文件，方便排查。

## 6. 验收要求（每个阶段）

```powershell
cargo build --release                 # 必须 0 error
cargo test --release                  # 相关测试必须全绿
.\target\release\wbwpty.exe -- cmd.exe /c echo hello
```

无 conhost 验证（必须真的做，不许只在文档里声称）：

```powershell
# 运行前后对比 conhost.exe 数量 / 进程树
.\target\release\wbwpty.exe --dump-conhost -- cmd.exe /c echo hello
```

## 7. 提交纪律

- 每个阶段结束立刻提交，**禁止只写代码不提交**。
- commit message 用 `<type>: <描述>`，type 取值：
  `chore` / `feat` / `fix` / `test` / `docs` / `perf` / `refactor`。
- 描述用英文（与阶段表格保持一致），一行说完"做了什么"，不要写"更新代码"这种废话。
- 提交前必须 `git status` 确认没有把 `target/`、`*.dll`、`*.log` 带进去（`.gitignore` 已覆盖，
  但仍要确认 `git add -A` 之后 `git status --short` 是干净且只有预期文件）。
- 最终必须 `git push -u origin main`（remote: `https://github.com/wbw121124/wbwpty.git`）。
  若凭证不可用，输出完整 `git log --oneline` + 可直接粘贴的 push 命令，**不许谎称已 push**。
- **已知例外**：`a137298`（message 是 `???`）与 `4ede9bb`（message 是 `awa`）两条不符合本节格式。
  它们在 2026-10-16 之前就已推到 origin，2026-10-16 决定**不重写历史**
  （改已发布历史需要 force-push，风险大于收益）。记在这里，别再"顺手修一下"。

## 8. 代码风格

- `rustfmt` 默认风格；行宽 100 以内。
- 注释写"为什么"，不写"做了什么"。注释里的事实必须有来源（文档名 / 头文件 / 实测）。
- 公开 API 用 `anyhow::Result`；内部模块用具体错误类型或 `Option`。
- 平台相关常量集中定义（例如 `const CONSOLE_HANDLE_SENTINEL: usize = 0x123;`），不要散落魔数。

## 9. 排障速查

| 现象 | 先查 |
| --- | --- |
| 注入后目标立刻退出 | DLL 的 `DllMain` 是否 panic/返回 FALSE；看 `WBWPTY_LOG` 与 DebugView |
| 目标没有输出 | 管道是否都创建成功；`SetStdHandle` 是否在 CRT 初始化之前完成 |
| 输出要等 4KB 才出现 | CRT 全缓冲；检查 `setvbuf(_IONBF)`（不是 `_IOLBF`，坑 21） |
| 子进程又冒出 conhost | ①目标自己的 `CreateProcessW` IAT 槽改了吗（`manual_map::hook`）；②supervisor 覆盖到那一代了吗（`Session::coverage()`）；③它是不是在自己起来几毫秒内就 spawn 了（坑 27） |
| `iced-x86` 在 no_std 下编译失败 | 退回手写 x64 长度解码器（在 `hook.rs` 里已留降级分支） |
| `ReadProcessMemory` 报 `ERROR_PARTIAL_COPY` | **目标里还没映射这个模块**。挂起进程只有 exe + ntdll，必须等 loader 跑完（见规则 7） |
| 目标一直不进入口点 | 见 README 5.3；先确认是不是"我们没动它也进不去" |

## 7'. 已踩过的坑（别再踩）

1. **挂起进程的 `PEB->Ldr` 是 NULL**。`CREATE_SUSPENDED` 时 loader 尚未运行，
   目标里除 exe 与 ntdll 外无任何映射，宿主与目标的 `KERNEL32.dll` 基址也不同
   （Shared mapping 只在同一 boot 的"已加载"进程间共享）。
   → 必须等 `PEB->Ldr` 可遍历再注入。注入策略改为：**先 resume，轮询稳定快照**。
2. **x64 PE 的重定位是 `IMAGE_REL_BASED_DIR64`(10)**，不是 `HIGHLOW`(3)。两个都要实现。
3. **手写 x64 机器码时 REX 前缀的 R/B 位极易写错**，而且错得很隐蔽
   （`mov r10, [r9]` 曾被编码成 `mov r9, [r9]`，`mov rcx, r11` 编成 `mov rcx, r9`）。
   → 每个 stub 都必须有**真正执行它**的单测（分配 RWX 页 + 真实跳转），
   光比对字节不够；字节比对再叠一层防回归。
4. `no_std` cdylib 必须自己导出 `rust_eh_personality`（sysroot 的 `core` 按 unwind 编译）。
5. 读 PE 数据目录/名字字符串要用 RVA→文件偏移的映射（`PeImage::read_rva`），
   直接拿 RVA 当文件偏移会读到垃圾。
6. **不能把挂起进程的入口点改成 `jmp`**：`cmd.exe` 这类 `GUARD_CF` 映像在入口点写入任何跳转指令，loader 就会以 `STATUS_POSSIBLE_DEADLOCK (0x103)` 杀死进程。其他 `.text` 位置写入完全无害，只有 entry point 敏感。
7. **Win64 FFI 第 2 参数在 `rdx`，不是 `r9`**：stub 写了 `mov r9d, 1` 想传 `DLL_PROCESS_ATTACH`，编译无错但 `DllMain` 拿到的 reason 是垃圾值，整条 attach 路径静默跳过，且 stub 依然返回 exit code 0（完全伪装成功）。必须用 `mov edx, 1`。
8. **`VirtualQueryEx` 报告 `MEM_FREE` 不代表可写**：必须用 `VirtualAllocEx` 真正 commit，否则 `WriteProcessMemory` 返回 `ERROR_INVALID_ADDRESS (998)`。
9. **x64 `IMAGE_THUNK_DATA64` 步进是 8 字节**：旧的 import resolver 按 16 字节步进，读取的 RVA 全是垃圾，表现成 `"string at 0x65e0ac22 is outside the image"`。
10. **`STARTF_USESTDHANDLES` 传管道句柄后，宿主必须立刻释放自己的客户端副本**：否则 `-out` 管道的 writer 永远不为空，`pump_output` 死等 EOF。
11. **`dlog!()` 在 loader lock 下会触发 AV**：`dlog!` 的格式化代码（`core::fmt`）在 no_std DLL 中会访问 PEB 偏移 `params+0x80`，超出 `RTL_USER_PROCESS_PARAMETERS` 实际大小（~0x60），导致 `STATUS_ACCESS_VIOLATION`。**DllMain 内禁止调用 `dlog!`**，改用直接写 `WBWPTY_STATUS` 状态字。
12. **目标启动前改写 `ConsoleHandle` 会直接杀死目标**：`0xC0000142`（`STATUS_DLL_INIT_FAILED`）。
    写成假句柄 `0x123` 会死，写成目标自己 `StandardOutput` 那种真实句柄**也**会死。
    启动过程中碰这个字段的唯一安全时机是 loader 跑完之后。
    回归测试：`session::tests::rewriting_the_console_handle_before_startup_kills_the_target`。
13. **`ConsoleHandle` 哨兵挡不住孙进程**（2026-10 实测推翻 README 1.2）：即使每 5ms 连续重申
    `0x123`，`cmd /c` 的孙进程照样拿到 9001×120 的 conhost。证据：进程树
    `wbwpty → cmd → cmd → conhost.exe`，以及孙进程自己的 `mode con` 有输出而顶层目标没有。
    **真正的开关是 `DETACHED_PROCESS` + `STARTF_USESTDHANDLES`，两半缺一不可**
    （完整矩阵见 README §1.2 与 `tests/descendant_creation.rs`）。
14. **`GetStdHandle(0..2)` 可能返回 `INVALID_HANDLE_VALUE`**，哪怕该进程的 stdout 是完全可用的
    管道。拿它去填子进程的 `STARTUPINFOW` = 传三个坏句柄，子进程立刻 exit 1。
    要传"本进程真正在写的句柄"就用 CRT 的 `as_raw_handle`。
15. **别用 `cmd.exe` 的输入回显来判断"孙进程有输出"**：交互式 cmd 会把你喂进去的命令行原样
    回显到 stdout。如果回显文本里含断言用的标记串，测试就会假阳性。
    `grandchild_output_reaches_the_pipe` 之前就是这么"通过"的。
    现在标记串用 `for %i in (NEU) do @echo %i7Q2K5` 拼出来，命令行里只有字面量 `%i`。
16. **计数 conhost 判据容易被短命进程骗过**：孙进程活得比采样还短时，`after` 与 `before`
    差值是竞态。要归因就抓进程树（`PROCESSENTRY32W::th32ParentProcessID`），
    并把子进程 pid 落盘以便归属；`inspect::conhost_parents()` 提供这个能力。
17. **测试里清理 console host 必须精确到自己的子进程**：早先版本杀掉"所有非基线 conhost 的
    父进程"，并行跑时把别的测试的 fixture 也杀了，表现为两个无关测试随机失败——
    看起来像被测对象有并发 bug。
18. **测试夹具之间不要共享进程级状态**：pidfile 走环境变量时，4 个并行测试互相覆盖；
    改走命令行参数。同理，夹具的失败必须用**不同的退出码**区分
    （spawn 失败 / wait 失败 / 取退出码失败），否则都表现为"exit 0"。
19. **`SystemTime::now()` 在 Windows 上约 15.6ms 分辨率**：同一 tick 内两次取样会得到相同值，
    拿它当 session nonce 会让两个会话撞管道名。`nonce()` 里混了原子计数器。
20. **`stable_modules()` 里第一次遍历失败不等于失败**：`LdrpInitializeProcess` 是逐个挂链的，
    跨过挂链点的遍历会触发 doubly-linked 校验失败。机器一忙就复现。
    现在两种遍历失败都当作"还没就绪"重试到超时。
21. **`setvbuf(_IOLBF)` 对管道完全没用**：实测 UCRT 的 `_IOLBF == 0x40` 对非 console 流
    行为和 `_IOFBF` 一样；真正能消除延迟的是 **`_IONBF == 4`**。UCRT 只接受 `0 / 4 / 0x40`
    三个值，其余（1,2,3,8,32,128）**返回 `EINVAL` 但不会 abort 进程**——探针照样活着，
    只是缓冲区行为跟全缓冲一样。
    这三个值跟 mingw 的不一样（mingw: 0/1/2），**别照头文件"修正"**。
    **判据必须是 `setvbuf` 的返回值，不是"进程还在不在"**：早期版本用进程存活当代理，
    结果在 `[0,4,0x40]` 和 `[0,2,3,4,8,0x20,0x40,0x80]` 之间来回跳（flaky）。
    完整扫描见 README §1.6 与 `tests/crt_buffering.rs`（探针会回报 `setvbuf(mode=N) -> RC`）。
22. **`_open_osfhandle` / `_dup2` 在本项目里用不上**：标准描述符本来就是会话管道，
    宿主在目标执行任何指令之前就通过 `STARTF_USESTDHANDLES` 交出去了。
    旧计划里的"完整 CRT 修复"包含它们，是照抄别的项目的做法，没有实测依据。
23. **目标项目的 stderr 和 stdout 是同一条管道**（`pipe.rs` 里 stderr 是 stdout 的副本），
    所以 shell 里 `2> file` 分不开它们，`--dump-conhost` 之类的输出要一起看。
24. **`SharedPipes::with` 返回 `Option<R>`，不是 `R`**：`with(|p| p.input().write_all(..))`
    的类型是 `Option<io::Result<()>>`，只写一个 `.expect()` 会把**内层 `Result` 静默丢掉**
    （告警 `unused Result that must be used`）。写管道要 `.expect(..).expect(..)` 两个。
25. **pid 单独存在时会被复用**：进程一退出 pid 就能被新进程拿走。
    往 pid 写内存（注入、打补丁）时**必须持有 `RemoteProcess` 句柄直到写完**——
    句柄让进程对象活着，pid 就不会被回收。`supervisor.rs` 整个处理过程都持有。
26. **后代可能是 32 位**：`remote.rs` 里每个 PEB 偏移都是 x64 的。
    把 x64 映像写进 WOW64 地址空间不是降级，是破坏。`RemoteProcess::is_x64_image()`
    读的是**目标自己的头**（不是磁盘文件），supervisor 拿它当拒绝条件。
27. **注入有 ~100ms 的时序窗口**：`stable_modules` 要两次快照一致才算就绪。
    目标在自己起来的前几毫秒内 spawn 的子进程，**赶在注入之前**——子进程就拿到自己的 console。
    这不是理论：`tests/grandchild_sentinel.rs` 的夹具就是这么失真的。
    → **夹具必须用 `--gate <file>` 把 spawn 时机交给测试**（见 `wbwpty-spawn-probe`），
    否则测的是竞态，不是功能。
28. **`--ignored` 的测试会弹真实的 conhost 窗口**。这是设计如此（它们测的就是那个 bug）。
    **跑之前必须把命令贴给用户、得到同意再跑**。`tests/descendant_injection.rs` 的
    两条是例外：设计上就不产生 conhost（其中一条还有运行时安全闸）。
29. **不要断言英文输出**：本机 `ping.exe` 是中文版，输出走 OEM 代码页，
    管道读出来是乱码。断言 "Pinging" 会对着一个**正常工作的功能**失败。
    断言 ASCII 的地址（`127.0.0.1`）这种与语言无关的东西。
30. **supervisor 的覆盖记录要边做边发**（`Session::coverage()`），不是结束时才汇总。
    "在它来得及 spawn 之前被接管"和"接管了但已经晚了"在输出上完全一样，
    只有时间戳能区分。
31. **挂起的进程注不进去**（2026-10-16 实测，两个独立的阻塞点）：
    - `CREATE_SUSPENDED` 出来的进程 `PEB->Ldr` 是 NULL，`stable_modules()` 永远等不到；
    - `inject_bytes` 末尾 `CreateRemoteThread(DllMain)` + `WaitForSingleObject(INFINITE)`，
      进程挂起时那个远程线程**根本不运行**，于是 `run_thread` 永久阻塞。
      实测后果：监督线程挂死 → `Drop for Session` join 它 → **测试整体挂住**
      （一次 `cargo test` 超过 300 秒不结束，留下孤儿 `cmd.exe`）。
    → "让子进程挂起直到被接管"这条路对本项目的注入器是**死路**，别再试。
    唯一可行的变体是把注入拆成"挂起期间只映射 + 改 IAT（纯数据写入），
    resume 之后再补 `CreateRemoteThread` 调入口"，见 README §1.7。
32. **测试里断言"目标还活着"会被 stdin EOF 毁掉**：input pump 把宿主 stdin 的 EOF
    变成管道 EOF，交互式 `cmd.exe` 立刻退出。要跑一个必须活着的目标，
    用 `SessionConfig { pump_input: false, .. }`——它不会去读宿主 stdin，
    也就不会替测试决定目标什么时候死。
33. **别用 `Start-Process cmd.exe /c "cargo test ..."` 当测试外壳**（2026-10-16 踩过）：
    承载它的 `pwsh.exe` 自己没有 console，于是**每跑一次测试就分配一个 console
    → 弹出一个 `conhost.exe`，有时还会带出 Windows Terminal 窗口**。
    这跟被测代码毫无关系，但用户看到的就是"测试在乱弹窗口"。
    正确做法是**直接在当前 shell 里调用**并重定向到文件：
    ```powershell
    & cargo test --workspace --release 2>&1 | Out-File $out -Encoding utf8
    ```
    套在 `cmd.exe /c` 里只是为了拿退出码和重定向，其实都不需要。
    核对方法：跑之前记一个时间戳，跑完数一下新增的 `conhost.exe`
    （父进程是 `pwsh.exe` 就说明是外壳而不是被测代码）。
34. **"探针还活着"不能当成"这个参数被接受了"**：`crt_buffering` 曾用进程存活来推断
    `setvbuf` 认不认某个 mode，结果在 `[0,4,0x40]` 和 `[0,2,3,4,8,0x20,0x40,0x80]`
    之间来回跳。UCRT 对非法 mode 只是 `return EINVAL` 并继续跑，**不 abort**。
    → 判据要用 API 自己的返回值（探针把它回报出来），别用间接代理指标。

## 10. 外部可复用模块（评估过再用）

- `wbw121124/wbwtty` 分支 `feature/pty-win10-early`：含渲染模块。
  恢复工作时优先评估复用它的渲染/虚拟屏层，而不是自己重写 VT 渲染。
  <https://github.com/wbw121124/wbwtty/tree/feature/pty-win10-early>

## 11. 2026-10-16 新增的坑（追 `cmd /c` 输出丢失，一整轮弯路）

这一轮为了查"后代输出不到管道"，先后否掉了**四个**错误假设。四个都"看起来"像证据，
因为每一次都能测到 `hook_stats == 0`。记住：**0 调用有五种完全不同的原因。**

1. **计数器在目标死后才读，永远是 `None`。**
   `payload_hook_stats()` 原本在会话结束后才读目标内存，短命目标早就没了。
   所以 `--verbose` 从来没打印过一次 hook 计数 —— 已装的 hook 和死掉的 hook
   从外面看一模一样。改为**目标存活期内采样 + 缓存**（计数单调，取高水位）。
   判据必须是采样，不是事后读。

2. **诊断的观测窗口必须等目标结束，不能写死秒数。**
   固定等 3 秒、而目标要 4.5 秒才跑完 —— 测出来 `hook=0`，对着一个完全正常的
   替换函数。诊断脚本要 `wait_for(target)`，不是 `sleep(3)`。

3. **`ChildSpec` 会给含空格的参数加引号，`cmd /c` 只剥外层那对。**
   结果内层引号以 `\"` 字面量到达命令解释器，`python -c` 的代码被吃掉，
   报 `NameError`/`AttributeError`，**子进程从没真正跑过**。
   含空格的路径在 `cmd /c` 场景用 8.3 短路径（`PROGRA~1`）或脚本文件。

4. **IAT 槽在 loader 解析前存的是 `IMAGE_IMPORT_BY_NAME` 指针。**
   它落在映像自身范围内（`[base, base+SizeOfImage)`）；解析后才是别的模块里的
   API 地址。原代码只查 `!= 0`，把 hint/name 指针当成真实地址发布出去、
   还把槽改写了 —— 装得干净、指针一度可见，随后 loader 又填回真的
   `CreateProcessW`。**改槽之前必须确认它不在映像范围内。**

5. **`cmd /c` 无延迟 spawn 早于注入完成。** 这是 §5.3 的真实限制，不是 bug。
   `cmd /k` + 输入命令能命中 hook（spawn 晚），`cmd /c <child>` 不能（spawn 早）。
   加 `ping -n N 127.0.0.1` 前缀把窗口拉开就能复现命中 —— **用这个前缀区分
   "替换不工作" 和 "替换还没装上"**。

6. **`cmd.exe` 用 `STARTUPINFOEXW`（`cb = 0x70` + `lpAttributeList`）调 CreateProcess。**
   - 别改 `cb`：改成 `0x68` 会直接 `ERROR_BAD_EXEFORMAT`。
   - 别把 `STARTUPINFOW` 拷进 0x68 字节的本地结构：`lpAttributeList` 在
     offset **0x68**（结构**内部**，不是后面），`cb=0x70` 让内核多读 8 字节栈垃圾，
     同样 `ERROR_BAD_EXEFORMAT`。

7. **目标重定向自己的 stdout，管道句柄就失效了（补充坑 23）。**
   `cmd /c "ping > nul & python"` 里 `> nul` 会关掉宿主给的管道句柄并
   `CreateFile("nul")` **复用同一个数值**。把这个失效句柄传给后代 →
   `GetStdHandle` 返回它（PEB 里的数值仍对）、`GetFileType` 却给
   `FILE_TYPE_UNKNOWN` → CRT 不给 fd 1 → `sys.stdout is None`。
   **判据要同时看 `GetStdHandle` 和 `GetFileType`**：只看前者会得出"句柄没问题"
   的错误结论。

8. **别强制 `bInheritHandles = TRUE`。** 试过，与 attribute list 冲突，
   `CreateProcess` 直接 `ERROR_BAD_EXEFORMAT`，比原样传递更糟。
   原样传递是对的（坑 13 那行的注释"handle inheritance on"是误读，实测 cmd 本来就传对了）。

9. **"第一代正常"不能推广到第二代。**
   宿主直接创建 python：`DETACHED_PROCESS + STARTF_USESTDHANDLES` 下三个 fd
   全是管道、`sys.stdout` 正常。同样的 flags 走 substitute 就坏 —— 所以问题
   一定在 substitute 传给内核的东西上，不在 flags，也不在 UCRT。

10. **别把子串当成导入名。** `CreateProcessA` 是 `CreateProcessAsUserW` 的**前缀子串**，
    扫二进制找字符串会"找到"一个根本不存在的导入。（`cmd.exe` 实际只导入
    `CreateProcessW` 和 `CreateProcessAsUserW`，且确实通过**自己的 IAT** 调用
    `CreateProcessW` —— 用 x64dbg 在 `CreateProcessW` 下断点、`rdx` 读到
    `ping -n 5 127.0.0.1` 实测确认。）

11. **重建后 `.text` 里的 RVA 会变。** 硬编码 `create_process_w` 的 RVA 去反推
    payload 基址，重新编译后读到的是**别的段**，得到一个 kernel32 地址这种
    "看起来合理"的垃圾。诊断脚本要从 DLL 导出表现算，别写死。

12. **小端读数要重组字节。** 把 `D024008001000000` 当一个十六进制数读等于
    `0xD024008001000000`；真值是 `0x1800024D0`。在错误地址下断点，
    脚本会理直气壮地报 "MISS"。

13. **自己的改动会制造出你要找的 bug。** 本轮 `fd 1 = INVALID_HANDLE_VALUE`
    一度被我当成根因，实际是前一步强制 `bInheritHandles=TRUE` 引入的；
    `git stash` 回退后同一条命令完全正常。**推翻一个假设前，先回退自己的改动。**

14. **本仓库缺 `wbwpty-spawn-probe` / `--gate`。** 旧文档引用过它们，当前树里
    不存在；写"按规则 27 用 gate 夹具"之前先确认它还在。

### 调试器怎么用（本轮实际有效的方式）

- `debug_init` 会把进程跑到结束，**停不下来**；真正可用的是
  `debug_attach_pid` + 先启动一个长命令留窗口。
- 系统断点（`rip` 落在 ntdll）时 cmd.exe 的模块已加载、用户代码还没跑 ——
  此时下断点最合适。
- `attach` 会话活不过一次慢往返，**附加+下断点+运行必须写在同一个脚本里**。
- 用 `cmd /c "ping -n 20 127.0.0.1 > nul & <被测命令>"` 拖出 ~20 秒窗口。
- x64dbg MCP 只在重启 opencode 后成为原生工具；配置在
  `~/.config/opencode/opencode.jsonc`（`type: "remote"`，`url: .../mcp`），
  没重启前可用 HTTP 桥接脚本直连。