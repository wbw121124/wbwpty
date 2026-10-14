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
| 输出要等 4KB 才出现 | CRT 全缓冲；检查 `setvbuf(_IOLBF)` 与"读输入前 `_flushall`"是否生效 |
| 子进程又冒出 conhost | `ConsoleHandle` 补丁是否生效（阶段 6）；std handle 是否标记可继承 |
| `iced-x86` 在 no_std 下编译失败 | 退回手写 x64 长度解码器（在 `hook.rs` 里已留降级分支） |