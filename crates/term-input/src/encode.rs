//! 事件 → VT 序列编码。
//!
//! 编码遵循 xterm 控制序列约定（CSI `ESC [`、SS3 `ESC O`、修饰参数 `1+Shift+Alt*2+Ctrl*4+Meta*8`）：
//! - 光标键：无修饰 + DECCKM(1) → `SS3 A`；否则 `CSI A`；带修饰一律 `CSI 1;mA`
//! - Insert/Delete/PgUp/PgDn/F5..F12 → `CSI n~`（带修饰 `CSI n;m~`）
//! - F1..F4 → `SS3 P/Q/R/S`（带修饰 `CSI 1;mP`…）
//! - 字符：Ctrl 取 C0 控制字节，Alt 前置 `ESC`；Shift+Tab → `CSI Z`
//! - 鼠标：LEGACY 32 偏移三字节（坐标封顶 223）/ SGR `<b;x;y M|m`（1006），1 起始坐标
//! - 模式门控：release 需 ≥1000、拖拽需 ≥1002、无键移动需 1003；滚轮/按键需任意鼠标模式

use crate::event::{
    InputEvent, KeyCode, KeyEvent, Modifiers, MouseEvent, MouseAction, NumpadKey,
};

/// 鼠标上报模式（DECSET 10/1000/1002/1003；Off = 全关）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MouseMode {
    #[default]
    Off,
    /// 10：仅按键/滚轮按下（不报释放）。
    X10,
    /// 1000：按键/滚轮按下与释放。
    Normal,
    /// 1002：+ 按键拖拽。
    Drag,
    /// 1003：+ 全部移动。
    Motion,
}

impl MouseMode {
    /// 序数（越大上报越多）。
    pub const fn rank(self) -> u8 {
        match self {
            MouseMode::Off => 0,
            MouseMode::X10 => 1,
            MouseMode::Normal => 2,
            MouseMode::Drag => 3,
            MouseMode::Motion => 4,
        }
    }

    fn allows(self, action: MouseAction) -> bool {
        match action {
            MouseAction::Press(_) | MouseAction::ScrollUp | MouseAction::ScrollDown => {
                self != MouseMode::Off
            }
            MouseAction::Release(_) => self.rank() >= MouseMode::Normal.rank(),
            MouseAction::Drag(_) => matches!(self, MouseMode::Drag | MouseMode::Motion),
            MouseAction::Move => self == MouseMode::Motion,
        }
    }
}

/// 鼠标坐标编码方式（DECSET 1006：SGR；否则 X10 legacy）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Encoding {
    #[default]
    Legacy,
    Sgr,
}

/// 输入编码器：持有终端模式，把事件编码为 VT 字节流。
///
/// 模式来源：vt-parser 检出 DECSET/DECRST（DECCKM/DECKPAM/10/1000/1002/1003/1006/2004）
/// 后调用对应 setter 回灌。
#[derive(Clone, Debug)]
pub struct Encoder {
    cursor_keys_app: bool,
    keypad_app: bool,
    mouse: MouseMode,
    encoding: Encoding,
    bracketed_paste: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// 复位状态：光标键常规、键盘常规、鼠标关、legacy 编码、bracketed paste 关。
    pub fn new() -> Self {
        Self {
            cursor_keys_app: false,
            keypad_app: false,
            mouse: MouseMode::Off,
            encoding: Encoding::Legacy,
            bracketed_paste: false,
        }
    }

    pub fn set_cursor_keys_app(&mut self, on: bool) {
        self.cursor_keys_app = on;
    }
    pub fn set_keypad_app(&mut self, on: bool) {
        self.keypad_app = on;
    }
    pub fn set_mouse_mode(&mut self, mode: MouseMode) {
        self.mouse = mode;
    }
    pub fn set_encoding(&mut self, enc: Encoding) {
        self.encoding = enc;
    }
    pub fn set_bracketed_paste(&mut self, on: bool) {
        self.bracketed_paste = on;
    }

    pub const fn cursor_keys_app(&self) -> bool {
        self.cursor_keys_app
    }
    pub const fn keypad_app(&self) -> bool {
        self.keypad_app
    }
    pub const fn mouse_mode(&self) -> MouseMode {
        self.mouse
    }
    pub const fn encoding(&self) -> Encoding {
        self.encoding
    }
    pub const fn bracketed_paste(&self) -> bool {
        self.bracketed_paste
    }

    /// 编码一个事件；`None` = 按当前模式不产生输出（如 Unidentified、被门控的鼠标移动）。
    pub fn encode(&self, ev: &InputEvent) -> Option<Vec<u8>> {
        match ev {
            InputEvent::Key(k) => self.encode_key(*k),
            InputEvent::Mouse(m) => self.encode_mouse(m),
            InputEvent::Paste(s) => Some(self.encode_paste(s)),
        }
    }

    /// 编码粘贴：bracketed paste 开启时包裹 `CSI 200~`/`CSI 201~`，否则原样。
    pub fn encode_paste(&self, text: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(text.len() + 16);
        if self.bracketed_paste {
            v.extend_from_slice(b"\x1b[200~");
            v.extend_from_slice(text.as_bytes());
            v.extend_from_slice(b"\x1b[201~");
        } else {
            v.extend_from_slice(text.as_bytes());
        }
        v
    }

    // ---- 按键 ---------------------------------------------------------------

    pub(crate) fn encode_key(&self, k: KeyEvent) -> Option<Vec<u8>> {
        let mods = k.mods;
        match k.code {
            KeyCode::Unidentified => None,
            KeyCode::Char(c) => Some(encode_char(c, mods)),
            KeyCode::Enter => Some(with_alt(b"\r".to_vec(), mods)),
            KeyCode::Tab => {
                if mods.contains(Modifiers::SHIFT) {
                    // Back Tab（ISOLeftTab）
                    Some(csi(b"Z".to_vec()))
                } else {
                    Some(with_alt(b"\t".to_vec(), mods))
                }
            }
            KeyCode::Backspace => {
                let base = if mods.contains(Modifiers::CTRL) { vec![0x08] } else { vec![0x7f] };
                Some(with_alt(base, mods))
            }
            KeyCode::Escape => Some(with_alt(vec![0x1b], mods)),
            // 光标/Home/End 类：终结字母
            KeyCode::Arrow(a) => Some(self.cursor_final(a.final_byte(), mods)),
            KeyCode::Home => Some(self.cursor_final(b'H', mods)),
            KeyCode::End => Some(self.cursor_final(b'F', mods)),
            // ~ 结尾功能键
            KeyCode::Insert => Some(tilde_key(2, mods)),
            KeyCode::Delete => Some(tilde_key(3, mods)),
            KeyCode::PageUp => Some(tilde_key(5, mods)),
            KeyCode::PageDown => Some(tilde_key(6, mods)),
            KeyCode::F(n) => function_key(n, mods),
            KeyCode::Numpad(n) => self.numpad(n, mods),
        }
    }

    /// 光标类序列：空修饰 + 应用模式 → SS3；空修饰 → CSI；带修饰 → CSI 1;mX。
    fn cursor_final(&self, letter: u8, mods: Modifiers) -> Vec<u8> {
        if mods.is_empty() && self.cursor_keys_app {
            ss3(letter)
        } else if mods.is_empty() {
            csi(vec![letter])
        } else {
            let mut v = vec![0x1b, b'[', b'1', b';'];
            push_u32(&mut v, 1 + mods.bits() as u32);
            v.push(letter);
            v
        }
    }

    /// 小键盘：应用模式（DECKPAM）发 SS3 映射，否则发常规字符。
    fn numpad(&self, k: NumpadKey, mods: Modifiers) -> Option<Vec<u8>> {
        if self.keypad_app {
            let fin: u8 = match k {
                NumpadKey::Num(c @ '0'..='9') => b'p' + (c as u8 - b'0'),
                NumpadKey::Num(_) => return None,
                NumpadKey::Decimal => b'n',
                NumpadKey::Enter => b'M',
                NumpadKey::Add => b'k',
                NumpadKey::Subtract => b'm',
                NumpadKey::Multiply => b'l',
                NumpadKey::Divide => b'o',
                NumpadKey::Equals => b'j',
            };
            return Some(ss3(fin));
        }
        let c: char = match k {
            NumpadKey::Num(c) => c,
            NumpadKey::Decimal => '.',
            NumpadKey::Enter => return Some(with_alt(b"\r".to_vec(), mods)),
            NumpadKey::Add => '+',
            NumpadKey::Subtract => '-',
            NumpadKey::Multiply => '*',
            NumpadKey::Divide => '/',
            NumpadKey::Equals => '=',
        };
        Some(encode_char(c, mods))
    }

    // ---- 鼠标 ---------------------------------------------------------------

    fn encode_mouse(&self, m: &MouseEvent) -> Option<Vec<u8>> {
        if !self.mouse.allows(m.action) {
            return None;
        }
        // 按钮码 + 运动位 + 修饰位
        let mut code: u8 = match m.action {
            MouseAction::Press(b) | MouseAction::Release(b) | MouseAction::Drag(b) => b.code(),
            MouseAction::Move => 3, // 无按键
            MouseAction::ScrollUp => 64,
            MouseAction::ScrollDown => 65,
        };
        if matches!(m.action, MouseAction::Drag(_) | MouseAction::Move) {
            code += 32; // motion 位
        }
        // 鼠标修饰位：Shift+4、Alt+8、Ctrl+16（与 Modifiers 的 1/2/4 位不同）
        if m.mods.contains(Modifiers::SHIFT) {
            code += 4;
        }
        if m.mods.contains(Modifiers::ALT) {
            code += 8;
        }
        if m.mods.contains(Modifiers::CTRL) {
            code += 16;
        }
        let release = matches!(m.action, MouseAction::Release(_));
        match self.encoding {
            Encoding::Sgr => Some(encode_mouse_sgr(code, m.col, m.row, release)),
            Encoding::Legacy => Some(encode_mouse_legacy(code, m.col, m.row)),
        }
    }
}

// ---- 纯函数助手 -------------------------------------------------------------

fn csi(rest: Vec<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(rest.len() + 2);
    v.extend_from_slice(b"\x1b[");
    v.extend_from_slice(&rest);
    v
}

fn ss3(final_byte: u8) -> Vec<u8> {
    vec![0x1b, b'O', final_byte]
}

/// 带修饰的 `~` 键：`CSI n~` 或 `CSI n;m~`。
fn tilde_key(num: u8, mods: Modifiers) -> Vec<u8> {
    let mut v = vec![0x1b, b'['];
    push_u32(&mut v, num as u32);
    if !mods.is_empty() {
        v.push(b';');
        push_u32(&mut v, 1 + mods.bits() as u32);
    }
    v.push(b'~');
    v
}

/// Alt 前置 ESC（仅用于 C0 类输出）。
fn with_alt(mut base: Vec<u8>, mods: Modifiers) -> Vec<u8> {
    if mods.contains(Modifiers::ALT) {
        let mut v = Vec::with_capacity(base.len() + 1);
        v.push(0x1b);
        v.append(&mut base);
        v
    } else {
        base
    }
}

/// 字符编码：Ctrl → C0 控制字节；Alt → ESC 前缀；否则 UTF-8。
///
/// Ctrl 映射（近似 xterm）：空格 → NUL、`?` → DEL、其余 ASCII → 大写后 `&0x1f`；
/// 非 ASCII 不做 Ctrl 变换。
fn encode_char(c: char, mods: Modifiers) -> Vec<u8> {
    let ctrl = mods.contains(Modifiers::CTRL);
    let mut bytes = if ctrl && c.is_ascii() {
        let b = if c == ' ' {
            0x00u8
        } else if c == '?' {
            0x7fu8
        } else {
            (c.to_ascii_uppercase() as u8) & 0x1f
        };
        vec![b]
    } else {
        let mut buf = [0u8; 4];
        c.encode_utf8(&mut buf).as_bytes().to_vec()
    };
    if mods.contains(Modifiers::ALT) {
        let mut v = Vec::with_capacity(bytes.len() + 1);
        v.push(0x1b);
        v.append(&mut bytes);
        v
    } else {
        bytes
    }
}

/// F1..=F12；超出范围 → None。
fn function_key(n: u8, mods: Modifiers) -> Option<Vec<u8>> {
    match n {
        1..=4 => {
            let fin = b"PQRS"[(n - 1) as usize];
            if mods.is_empty() {
                Some(ss3(fin))
            } else {
                let mut v = vec![0x1b, b'[', b'1', b';'];
                push_u32(&mut v, 1 + mods.bits() as u32);
                v.push(fin);
                Some(v)
            }
        }
        5..=12 => {
            let num: u8 = match n {
                5 => 15,
                6 => 17,
                7 => 18,
                8 => 19,
                9 => 20,
                10 => 21,
                11 => 23,
                _ => 24,
            };
            Some(tilde_key(num, mods))
        }
        _ => None,
    }
}

/// SGR 鼠标（DECSET 1006）：`CSI < code ; col ; row M/m`。
fn encode_mouse_sgr(code: u8, col: u16, row: u16, release: bool) -> Vec<u8> {
    let mut v = vec![0x1b, b'[', b'<'];
    push_u32(&mut v, code as u32);
    v.push(b';');
    push_u32(&mut v, col as u32);
    v.push(b';');
    push_u32(&mut v, row as u32);
    v.push(if release { b'm' } else { b'M' });
    v
}

/// Legacy X10 鼠标：`CSI M` + (32+code) + (32+col) + (32+row)；坐标封顶 223。
fn encode_mouse_legacy(code: u8, col: u16, row: u16) -> Vec<u8> {
    let c = col.min(223) as u32 + 32;
    let r = row.min(223) as u32 + 32;
    vec![0x1b, b'[', b'M', 32 + code, c as u8, r as u8]
}

fn push_u32(v: &mut Vec<u8>, n: u32) {
    if n >= 10 {
        push_u32(v, n / 10);
    }
    v.push(b'0' + (n % 10) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ArrowKey, MouseButton};

    fn key(code: KeyCode, mods: Modifiers) -> Vec<u8> {
        Encoder::new().encode_key(KeyEvent::new(code, mods)).expect("encode")
    }

    fn plain(code: KeyCode) -> Vec<u8> {
        key(code, Modifiers::NONE)
    }

    #[test]
    fn plain_char_and_utf8() {
        assert_eq!(plain(KeyCode::Char('a')), b"a");
        assert_eq!(plain(KeyCode::Char('中')), "中".as_bytes());
    }

    #[test]
    fn ctrl_and_alt_chars() {
        assert_eq!(key(KeyCode::Char('c'), Modifiers::CTRL), vec![0x03]);
        assert_eq!(key(KeyCode::Char('C'), Modifiers::CTRL), vec![0x03]);
        assert_eq!(key(KeyCode::Char(' '), Modifiers::CTRL), vec![0x00]);
        assert_eq!(key(KeyCode::Char('?'), Modifiers::CTRL), vec![0x7f]);
        assert_eq!(key(KeyCode::Char('a'), Modifiers::ALT), vec![0x1b, b'a']);
        assert_eq!(
            key(KeyCode::Char('c'), Modifiers::CTRL | Modifiers::ALT),
            vec![0x1b, 0x03]
        );
    }

    #[test]
    fn control_keys() {
        assert_eq!(plain(KeyCode::Enter), b"\r");
        assert_eq!(plain(KeyCode::Tab), b"\t");
        assert_eq!(key(KeyCode::Tab, Modifiers::SHIFT), b"\x1b[Z");
        assert_eq!(plain(KeyCode::Backspace), vec![0x7f]);
        assert_eq!(key(KeyCode::Backspace, Modifiers::CTRL), vec![0x08]);
        assert_eq!(plain(KeyCode::Escape), vec![0x1b]);
        assert_eq!(key(KeyCode::Enter, Modifiers::ALT), vec![0x1b, b'\r']);
        assert_eq!(
            Encoder::new().encode(&InputEvent::Key(KeyEvent::plain(KeyCode::Unidentified))),
            None
        );
    }

    #[test]
    fn arrows_regular_and_app_and_mods() {
        let e = Encoder::new();
        assert_eq!(
            e.encode_key(KeyEvent::plain(KeyCode::Arrow(ArrowKey::Up))),
            Some(b"\x1b[A".to_vec())
        );
        let mut app = Encoder::new();
        app.set_cursor_keys_app(true);
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Arrow(ArrowKey::Up))),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Arrow(ArrowKey::Left))),
            Some(b"\x1bOD".to_vec())
        );
        // 带修饰：两种模式都走 CSI 1;mX（Shift+Ctrl → 1+1+4=6）
        let mods = Modifiers::SHIFT | Modifiers::CTRL;
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::Arrow(ArrowKey::Up), mods)),
            Some(b"\x1b[1;6A".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::new(KeyCode::Arrow(ArrowKey::Down), mods)),
            Some(b"\x1b[1;6B".to_vec())
        );
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::Arrow(ArrowKey::Right), Modifiers::ALT)),
            Some(b"\x1b[1;3C".to_vec())
        );
    }

    #[test]
    fn home_end_and_tilde_keys() {
        let e = Encoder::new();
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::Home)), Some(b"\x1b[H".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::End)), Some(b"\x1b[F".to_vec()));
        let mut app = Encoder::new();
        app.set_cursor_keys_app(true);
        assert_eq!(app.encode_key(KeyEvent::plain(KeyCode::Home)), Some(b"\x1bOH".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::Insert)), Some(b"\x1b[2~".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::PageUp)), Some(b"\x1b[5~".to_vec()));
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::Delete, Modifiers::CTRL)),
            Some(b"\x1b[3;5~".to_vec())
        );
    }

    #[test]
    fn function_keys() {
        let e = Encoder::new();
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::F(1))), Some(b"\x1bOP".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::F(4))), Some(b"\x1bOS".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::F(5))), Some(b"\x1b[15~".to_vec()));
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::F(12))), Some(b"\x1b[24~".to_vec()));
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::F(5), Modifiers::SHIFT)),
            Some(b"\x1b[15;2~".to_vec())
        );
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::F(2), Modifiers::ALT)),
            Some(b"\x1b[1;3Q".to_vec())
        );
        assert_eq!(e.encode_key(KeyEvent::plain(KeyCode::F(13))), None);
    }

    #[test]
    fn numpad_modes() {
        let mut app = Encoder::new();
        app.set_keypad_app(true);
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Num('5')))),
            Some(b"\x1bOu".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Num('0')))),
            Some(b"\x1bOp".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Decimal))),
            Some(b"\x1bOn".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Enter))),
            Some(b"\x1bOM".to_vec())
        );
        assert_eq!(
            app.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Add))),
            Some(b"\x1bOk".to_vec())
        );

        let e = Encoder::new();
        assert_eq!(
            e.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Num('5')))),
            Some(b"5".to_vec())
        );
        assert_eq!(
            e.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Subtract))),
            Some(b"-".to_vec())
        );
        assert_eq!(
            e.encode_key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Enter))),
            Some(b"\r".to_vec())
        );
        assert_eq!(
            e.encode_key(KeyEvent::new(KeyCode::Numpad(NumpadKey::Num('7')), Modifiers::ALT)),
            Some(vec![0x1b, b'7'])
        );
    }

    #[test]
    fn paste_bracketed_toggle() {
        let mut e = Encoder::new();
        assert_eq!(e.encode_paste("hi"), b"hi");
        e.set_bracketed_paste(true);
        assert_eq!(e.encode_paste("hi"), b"\x1b[200~hi\x1b[201~");
        assert_eq!(
            e.encode(&InputEvent::Paste("x".into())),
            Some(b"\x1b[200~x\x1b[201~".to_vec())
        );
    }

    #[test]
    fn mouse_legacy_press_and_cap() {
        let mut e = Encoder::new();
        e.set_mouse_mode(MouseMode::Normal);
        let m = MouseEvent::new(MouseAction::Press(MouseButton::Left), 1, 1, Modifiers::NONE);
        // 32+0, 32+1, 32+1
        assert_eq!(e.encode(&InputEvent::Mouse(m)), Some(vec![0x1b, b'[', b'M', 32, 33, 33]));
        // 坐标封顶 223 → 字节 255
        let big = MouseEvent::new(MouseAction::Press(MouseButton::Left), 500, 500, Modifiers::NONE);
        assert_eq!(e.encode(&InputEvent::Mouse(big)), Some(vec![0x1b, b'[', b'M', 32, 255, 255]));
        // 滚轮：64/65
        let up = MouseEvent::new(MouseAction::ScrollUp, 10, 20, Modifiers::NONE);
        assert_eq!(e.encode(&InputEvent::Mouse(up)), Some(vec![0x1b, b'[', b'M', 32 + 64, 42, 52]));
    }

    #[test]
    fn mouse_sgr_press_release_wheel() {
        let mut e = Encoder::new();
        e.set_mouse_mode(MouseMode::Normal);
        e.set_encoding(Encoding::Sgr);
        let press = MouseEvent::new(MouseAction::Press(MouseButton::Right), 5, 9, Modifiers::NONE);
        assert_eq!(e.encode(&InputEvent::Mouse(press)), Some(b"\x1b[<2;5;9M".to_vec()));
        let rel = MouseEvent::new(MouseAction::Release(MouseButton::Right), 5, 9, Modifiers::NONE);
        assert_eq!(e.encode(&InputEvent::Mouse(rel)), Some(b"\x1b[<2;5;9m".to_vec()));
        let wheel = MouseEvent::new(MouseAction::ScrollDown, 1, 1, Modifiers::SHIFT);
        // 65+4(shift)=69
        assert_eq!(e.encode(&InputEvent::Mouse(wheel)), Some(b"\x1b[<69;1;1M".to_vec()));
        // 拖拽需 1002（Drag）模式
        e.set_mouse_mode(MouseMode::Drag);
        let drag = MouseEvent::new(MouseAction::Drag(MouseButton::Left), 3, 4, Modifiers::CTRL);
        // 0+32(motion)+16(ctrl)=48
        assert_eq!(e.encode(&InputEvent::Mouse(drag)), Some(b"\x1b[<48;3;4M".to_vec()));
    }

    #[test]
    fn mouse_mode_gating() {
        let off = Encoder::new();
        let press = MouseEvent::new(MouseAction::Press(MouseButton::Left), 1, 1, Modifiers::NONE);
        assert_eq!(off.encode(&InputEvent::Mouse(press)), None);

        let mut x10 = Encoder::new();
        x10.set_mouse_mode(MouseMode::X10);
        assert!(x10.encode(&InputEvent::Mouse(press)).is_some());
        let rel = MouseEvent::new(MouseAction::Release(MouseButton::Left), 1, 1, Modifiers::NONE);
        assert_eq!(x10.encode(&InputEvent::Mouse(rel)), None, "X10 不报释放");

        let mut normal = Encoder::new();
        normal.set_mouse_mode(MouseMode::Normal);
        assert!(normal.encode(&InputEvent::Mouse(rel)).is_some());
        let drag = MouseEvent::new(MouseAction::Drag(MouseButton::Left), 1, 1, Modifiers::NONE);
        assert_eq!(normal.encode(&InputEvent::Mouse(drag)), None, "1000 不报拖拽");

        let mut drag_mode = Encoder::new();
        drag_mode.set_mouse_mode(MouseMode::Drag);
        assert!(drag_mode.encode(&InputEvent::Mouse(drag)).is_some());
        let move_ev = MouseEvent::new(MouseAction::Move, 1, 1, Modifiers::NONE);
        assert_eq!(drag_mode.encode(&InputEvent::Mouse(move_ev)), None, "1002 不报移动");

        let mut motion = Encoder::new();
        motion.set_mouse_mode(MouseMode::Motion);
        assert!(motion.encode(&InputEvent::Mouse(move_ev)).is_some());
    }
}
