# term-input（vendored）

来自 [wbw121124/wbwtty](https://github.com/wbw121124/wbwtty) 的 `feature/pty-win10-early`
分支，路径 `crates/term-input`，2026-10-16 取。

理由、纪律与同步方法与 `crates/vt-parser/README.md` 相同：源码逐字节照抄，
改动一律加在外面（`wbwpty-core` 里）。

配套关系：它把按键/鼠标事件编码成 VT 字节，而 `vt-parser` 的 `Terminal`
持有目标当前处于哪些模式（`application_cursor_keys()`、`bracketed_paste()`、
`mouse_mode()`、`application_keypad()`）。**编码必须查这些模式**——
同一个方向键在 DECCKM 开与关时发出的字节不同，这正是它存在的理由。