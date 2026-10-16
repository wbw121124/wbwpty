//! 平台无关输入事件类型。

/// 修饰键集合（自实现 bitflags，零依赖）。
///
/// 位布局与 xterm 修饰参数一致：Shift=1、Alt(Meta2)=2、Ctrl=4、Meta(8)=8；
/// 编码时参数值 = 1 + 各位置位值。
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Hash)]
pub struct Modifiers(u8);

impl Modifiers {
    pub const NONE: Self = Self(0);
    pub const SHIFT: Self = Self(1);
    pub const ALT: Self = Self(2);
    pub const CTRL: Self = Self(4);
    pub const META: Self = Self(8);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for Modifiers {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Modifiers {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// 方向键。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ArrowKey {
    Up,
    Down,
    Left,
    Right,
}

impl ArrowKey {
    /// CSI/SS3 终结字母（xterm 约定）。
    pub const fn final_byte(self) -> u8 {
        match self {
            ArrowKey::Up => b'A',
            ArrowKey::Down => b'B',
            ArrowKey::Right => b'C',
            ArrowKey::Left => b'D',
        }
    }
}

/// 小键盘按键（DECKPAM 应用键盘映射见 encode 模块）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum NumpadKey {
    /// 数字（'0'..='9'）。
    Num(char),
    /// 小数点/删除。
    Decimal,
    Enter,
    Add,
    Subtract,
    Multiply,
    Divide,
    Equals,
}

/// 键码。
///
/// 平台适配层负责归一化：大小写后的最终字符进 `Char`、ISOLeftTab → `Tab`+SHIFT。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum KeyCode {
    Char(char),
    Enter,
    Tab,
    Backspace,
    Escape,
    Insert,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    Arrow(ArrowKey),
    /// F1..=F12（超出范围不编码，encode 返回 None）。
    F(u8),
    Numpad(NumpadKey),
    /// 无法识别：不产生输出。
    Unidentified,
}

/// 键事件。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub mods: Modifiers,
}

impl KeyEvent {
    pub const fn new(code: KeyCode, mods: Modifiers) -> Self {
        Self { code, mods }
    }

    pub const fn plain(code: KeyCode) -> Self {
        Self { code, mods: Modifiers::NONE }
    }
}

/// 鼠标按键。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    /// 第 4/5 键（后退/前进）。
    X1,
    X2,
}

impl MouseButton {
    /// 编码按钮号（xterm：0/1/2/3/4）。
    pub const fn code(self) -> u8 {
        match self {
            MouseButton::Left => 0,
            MouseButton::Middle => 1,
            MouseButton::Right => 2,
            MouseButton::X1 => 3,
            MouseButton::X2 => 4,
        }
    }
}

/// 鼠标动作。
///
/// 坐标一律 **1 起始**（xterm 惯例），由调用方从控件坐标换算。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum MouseAction {
    Press(MouseButton),
    Release(MouseButton),
    Drag(MouseButton),
    /// 无按键移动（仅 1003 上报）。
    Move,
    ScrollUp,
    ScrollDown,
}

/// 鼠标/滚轮事件。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct MouseEvent {
    pub action: MouseAction,
    pub col: u16,
    pub row: u16,
    pub mods: Modifiers,
}

impl MouseEvent {
    pub const fn new(action: MouseAction, col: u16, row: u16, mods: Modifiers) -> Self {
        Self { action, col, row, mods }
    }
}

/// 统一输入事件。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InputEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    /// 粘贴文本（是否包裹 200~/201~ 由 Encoder 的 bracketed paste 状态决定）。
    Paste(String),
}
