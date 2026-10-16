//! vt-parser — VT 序列解析与终端屏幕状态。
//!
//! 零平台依赖：任何目标上都可构建与测试。数据流：
//!
//! ```text
//! 子进程字节流 -> feed() -> UTF-8 增量解码 -> 解析状态机 -> 屏幕状态变更
//! 客户端 -> get_screen() -> 单元格网格 + damage 行 + 光标状态
//! ```
//!
//! 公开 API：[`Terminal`]、[`ScreenView`]、[`Cell`]、[`Color`]、[`Attrs`]。

mod decode;
mod parser;
mod screen;
mod terminal;
mod width;

pub use screen::{Attrs, Cell, Color, CursorState, Pen, ScreenView};
pub use terminal::{
    MouseEncoding, MouseMode, Terminal, TerminalOptions,
};
pub use width::char_width;
