//! term-input — 键鼠/滚轮/paste 事件 → VT 序列编码（纯逻辑，零平台依赖）。
//!
//! 设计：
//! - [`event`]：平台无关的输入事件类型（由调用方从 GTK/Qt/Win32 事件翻译而来）
//! - [`encode`]：[`Encoder`] 持有终端模式（DECCKM、DECKPAM、鼠标模式 1000/1002/1003、
//!   SGR 1006、bracketed paste 2004），把事件编码为字节流
//!
//! 模式由终端侧回灌：vt-parser 检测到 DECSET/DECRST 后调用 Encoder 对应 setter，
//! 保证输入编码与当前终端状态一致（application cursor keys、keypad、鼠标上报等）。

pub mod encode;
pub mod event;

pub use encode::{Encoding, Encoder, MouseMode};
pub use event::{
    ArrowKey, InputEvent, KeyCode, KeyEvent, Modifiers, MouseButton, MouseEvent, MouseAction,
    NumpadKey,
};
