# vt-parser（vendored）

来自 [wbw121124/wbwtty](https://github.com/wbw121124/wbwtty) 的 `feature/pty-win10-early`
分支，路径 `crates/vt-parser`，2026-10-16 取。

## 为什么要 vendor 而不是依赖

上游所有 crate 都是 `publish = false` + `path` 依赖，没法按 git 依赖引入；
两个仓库都是 `wbw121124` 的，所以直接拷源码进来。

## 为什么不改里面的代码

**`src/` 与 `tests/` 与上游逐字节一致**，方便以后重新同步。改动一律加在外面
（`wbwpty-core` 里），不要在这个目录里动。

## 为什么它是对的依赖

- 纯 Rust，**零平台依赖**（上游 `Cargo.toml` 的 `[dependencies]` 是空的），
  所以不违反 AGENTS 规则 2（本机没有 MSVC，不引 `cc` 编的 C 代码）
- 自带 19 条单测（`src/terminal.rs` 内）+ `tests/vtseq.rs`，
  覆盖的恰好是难边界：UTF-8 跨 `feed` 切分、宽字符与组合字符、备用屏、
  滚动区与原点模式、SGR truecolor、DECALN、REP、DA/DSR 应答、resize 保持内容

## 同步方法

```powershell
$base = "https://raw.githubusercontent.com/wbw121124/wbwtty/feature/pty-win10-early/crates/vt-parser"
foreach ($f in @("src/decode.rs","src/parser.rs","src/screen.rs","src/terminal.rs","src/width.rs","src/lib.rs","tests/vtseq.rs")) {
  Invoke-WebRequest "$base/$f" -OutFile "crates/vt-parser/$f" -UseBasicParsing
}
```

同步后跑 `cargo test -p vt-parser`，它自己的测试必须全绿。