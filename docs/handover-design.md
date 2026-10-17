# 同步接管协议设计（草案，待评审）

## 1. 要解决的问题

`cmd.exe /c <command>` 会 spawn 孙进程。实测（2026-10-17，本机）：

| 时刻 | 事件 |
|---|---|
| 0 ms | `CreateProcessW(cmd.exe, DETACHED_PROCESS\|CREATE_SUSPENDED)` |
| 1.2 ms | 目标的 `PEB->Ldr` 可遍历（仅 3 个模块） |
| ~30 ms | cmd 自己的 loader 解析完 IAT，**cmd 从此可以 spawn** |
| ~35 ms | **cmd spawn 了 `ping`**（hook 尚未就绪） |
| 49 ms | 宿主完成 `CreateProcessW` 替换安装 |
| 更晚 | supervisor 发现 `ping` 已存在并创建了 `conhost.exe` |

内核在 `ping` 诞生那一刻就为它分配了 console。事后再注入、改 `ConsoleHandle` 都改不回去——实测确实
`injected=true hooked=true sentinel=true`，但 conhost 已经在了。

**结论**：这是时序问题，不是覆盖问题。缩短轮询间隔只是把赌注押小。

## 2. 现状为什么不够

`supervisor.rs` 靠轮询进程表发现后代（默认 3 ms）。它与目标的首个 spawn 赛跑，实测**输了**。

`hook.rs` 里还有两处轮询（L223 等槽值离开映像范围、L274 连续两次读回确认），合计约 15 ms。
即使这两处归零，cmd 在 ~30 ms 就能 spawn，窗口仍然存在。

已经做完的、必要的铺垫（见 `b307fff`）：payload 从导入 6 个 DLL 降到只导入 `KERNEL32.dll`，
注入时延 59 ms → 49 ms。**没有这一步，同步接管的宿主侧也无法在 cmd 可 spawn 之前完成注入。**

## 3. 方案：父进程主动交接

让**创建者**而不是**宿主**成为孙进程的发现者。创建者在把子进程放行之前，
先把它交给宿主。

### 3.1 时序

```
父进程                     宿主                        子进程
  |                         |                            |
  | CreateProcessW          |                            |
  |   + CREATE_SUSPENDED    |                            |
  |------------------------>|  (进程已存在，但未执行)     |
  |                         |                            |
  | 写 WBWPTY_PENDING_PID   |                            |
  |  = child_pid            |                            |
  |------------------------>| supervisor 轮询读到        |
  |                         |  向子进程注入 payload       |
  |                         |  安装 CreateProcess 替换    |
  |                         |                            |
  |                         | 写 WBWPTY_GATE = 1         |
  |                         |--------------------------->|
  | 读到 GATE == 1          |                            |
  | ResumeThread(child)     |                            |
  | 返回给原始调用者        |                            |
  |                         |                            |
  | 子进程从第一条指令开始就是"已被接管"的
```

关键性质：**子进程执行任何用户代码之前，替换已经就位**。
`CREATE_SUSPENDED` 让子进程停在入口点第一条指令之前。

### 3.2 载体

复用已有的导出机制，不引入新通道。`wbwpty-redirect` 的 `WBWPTY_*` 都是 `#[no_mangle] pub static mut`，
宿主用 `WriteProcessMemory` 写、`ReadProcessMemory` 读。这条路已经在用（句柄、flags、原始地址都是这么传的）。

新增两个导出字：

```rust
/// 父进程正在交接的子进程 pid；0 表示没有交接在进行。
#[no_mangle]
pub static mut WBWPTY_PENDING_PID: u32 = 0;

/// 宿主写 1 放行子进程；父进程在此之前一直阻塞。
#[no_mangle]
pub static mut WBWPTY_GATE: u32 = 0;
```

每个目标进程各有一份（payload 是按进程映射的），互不干扰。

### 3.3 payload 侧

`create_process_w` 的替身在调内核之前：

1. `flags = force_flags(dw_creation_flags) | CREATE_SUSPENDED`
2. 调真正的 `CreateProcessW`，拿到 `PROCESS_INFORMATION`
3. `WBWPTY_PENDING_PID = pi.dwProcessId`
4. 自旋等待 `WBWPTY_GATE == 1`，每次 `Sleep(0)` 或 `Sleep(1)`，**带超时**
5. `ResumeThread(pi.hThread)`
6. 清 `WBWPTY_PENDING_PID`，返回

### 3.4 宿主侧

`supervisor.rs` 的轮询循环里，在扫进程表之外加一条：**读根进程的 `WBWPTY_PENDING_PID`**。
非 0 就是一个待接管子进程：

1. 打开该 pid
2. 注入 payload（复用现有 `attempt()`）
3. 安装 `CreateProcess` 替换
4. `WriteProcessMemory` 写根进程的 `WBWPTY_GATE = 1`
5. `ResumeThread`

## 4. 必须处理的问题

### 4.1 注入失败怎么办？★最重要★

如果第 3.4 节第 2 步失败而我们不放行，**子进程永久挂起**，父进程也永久阻塞——整个会话死锁。
如果直接放行，就退回到今天的行为（子进程拿 console）。

选择：**超时后放行，并记录失败**。

- payload 侧等待有上限（建议 2000 ms），超时即自行 `ResumeThread`
- 这保证"最坏情况 = 今天的行为"，而不是"最坏情况 = 挂死"
- 宿主在 `Coverage.note` 里区分 `HandoverTimedOut`，让失败可见而不是被静默吞掉

### 4.2 父进程自己卡住怎么办？

父进程在 `CreateProcessW` 返回路径上阻塞，意味着它自己的 `CreateProcessW` 调用变慢。
如果宿主进程死了，子进程会等到 payload 的超时才放行（4.1 的超时兜住了）。
代价是会话最多延迟 2 s，不会永久卡住。

### 4.3 嵌套（孙辈创建曾孙辈）

子进程被放行后，它已经有可工作的替换，于是它创建下一代时会重复同一协议。**逐代自洽**，
不需要宿主特判。这是这个方案相对轮询的根本优势。

### 4.4 目标不用我们的替换怎么办？

如果目标根本不导入 `CreateProcessW`（`wanted.is_empty()`），它不会执行交接协议。
父进程侧的 `WBWPTY_PENDING_PID` 永远是 0，宿主什么都不做，退回今天的行为。安全。

### 4.5 32 位后代

沿用现有拒绝条件（`is_x64_image`）。宿主拒绝后**必须放行**，否则又是一次挂死。

### 4.6 与 CREATE_SUSPENDED 的交互

父进程原本可能自己就传了 `CREATE_SUSPENDED`（cmd 就这么干）。
- 若原本就有：交接后宿主放行前不要 `ResumeThread`，要让调用者决定
- 简化方案：记录原始 flags，只在**我们**添加的那一位时 resume

## 5. 不做什么

- **不**把挂起作为通用机制应用到所有后代（AGENTS §7' 坑 31：挂起进程注不进去，`run_thread` 会永久阻塞）
- **不**缩短 supervisor 的轮询间隔当作修复
- **不**碰入口点（AGENTS 坑 6：`GUARD_CF` 映像入口点被改会 `STATUS_POSSIBLE_DEADLOCK`）
- **不**引入 ConPTY / winpty / WSL / SSH（规则 1）

## 6. 验收标准

按已定的口径，三条都要满足才算通过：

1. 孙辈进程 `injected=true`
2. `CreateProcessW` 的 IAT 槽指向替身，且替身**确实被调用**（hook 计数 > 0）
3. 传给内核的标志含 `DETACHED_PROCESS`，且**整棵进程树零 `conhost.exe` / `OpenConsole.exe`**

新增测试：`a_ping_delay_creates_no_console_host_in_the_tree`
（已写好，当前**失败**，正是本方案要修的那个）

```
a console host was created under this test's tree while `ping` was running:
[Born { pid: 15636, parent: 4824, name: Some("conhost.exe") }]
```

## 7. 实现顺序

1. payload 侧：两个导出字 + 交接逻辑（含 4.1 超时）
2. 宿主侧：读 `PENDING_PID` → 注入 → 写 `GATE`
3. 单测：验证子进程在门闩前不执行
4. 跑 `a_ping_delay_creates_no_console_host_in_the_tree`，看是否转绿
5. 全量 `cargo test --workspace --release`
6. 更新 AGENTS.md §7'（新增坑）与 README §1.7

## 8. 待确认

- 4.1 的超时时长：2000 ms 是否合适？（太短会让注入稍慢的目标误判失败，太长会拖慢挂死恢复）
- 4.6 是否需要在协议里区分"调用者自己传了 CREATE_SUSPENDED"，还是先统一 resume、由调用者自行处理？