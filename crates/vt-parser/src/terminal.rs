//! 顶层 [`Terminal`]：字节 feed -> 屏幕状态；模式跟踪与应答生成。

use crate::parser::{Handler, Parser};
use crate::screen::{Attrs, Color, Pen, Screen, ScreenView};
use crate::decode::Utf8Decoder;
use crate::width::char_width;

/// 鼠标上报模式（DECSET 1000/1002/1003）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MouseMode {
    None,
    /// 1000：仅按下/释放。
    Normal,
    /// 1002：按下/释放 + 拖动。
    Button,
    /// 1003：任意移动。
    Any,
}

/// 鼠标编码（DECSET 1006）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MouseEncoding {
    /// X10/UTF-8 传统编码。
    Legacy,
    /// SGR（CSI < ... M/m）。
    Sgr,
}

/// 构造选项。
#[derive(Clone, Copy, Debug)]
pub struct TerminalOptions {
    /// 主屏回滚缓冲行数上限（0 = 无回滚）。
    pub scrollback_limit: usize,
}

impl Default for TerminalOptions {
    fn default() -> Self {
        Self { scrollback_limit: 10_000 }
    }
}

/// 终端状态机。线程内使用，不保证 Send 共享（自己包 Mutex）。
pub struct Terminal {
    decoder: Utf8Decoder,
    parser: Parser,
    core: TermCore,
}

impl Terminal {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self::with_options(cols, rows, TerminalOptions::default())
    }

    pub fn with_options(cols: u16, rows: u16, opts: TerminalOptions) -> Self {
        Self {
            decoder: Utf8Decoder::new(),
            parser: Parser::new(),
            core: TermCore::new(cols, rows, opts.scrollback_limit),
        }
    }

    /// 喂入字节（可任意切分，UTF-8 与序列状态跨调用保持）。
    pub fn feed(&mut self, bytes: &[u8]) {
        let Self { decoder, parser, core } = self;
        decoder.feed(bytes, |c| parser.feed(c, core));
    }

    /// 当前屏幕快照（主屏或备用屏）+ damage。
    pub fn get_screen(&self) -> ScreenView {
        self.core.screen_view()
    }

    /// 清除 damage 记录（渲染完成后调用）。
    pub fn clear_damage(&mut self) {
        self.core.active_mut().clear_damage();
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.core.resize(cols, rows);
    }

    pub fn title(&self) -> &str {
        &self.core.title
    }

    pub fn icon_title(&self) -> &str {
        &self.core.icon_title
    }

    pub fn mouse_mode(&self) -> MouseMode {
        self.core.mouse_mode()
    }

    pub fn mouse_encoding(&self) -> MouseEncoding {
        self.core.mouse_encoding
    }

    pub fn bracketed_paste(&self) -> bool {
        self.core.bracketed_paste
    }

    pub fn focus_reporting(&self) -> bool {
        self.core.focus_reporting
    }

    /// DECCKM：应用光标键模式（term-input 编码用）。
    pub fn application_cursor_keys(&self) -> bool {
        self.core.application_cursor_keys
    }

    /// DECKPAM：应用小键盘模式。
    pub fn application_keypad(&self) -> bool {
        self.core.application_keypad
    }

    pub fn insert_mode(&self) -> bool {
        self.core.insert_mode
    }

    pub fn is_alt_screen(&self) -> bool {
        self.core.alt.is_some()
    }

    pub fn bell_count(&self) -> u64 {
        self.core.bell_count
    }

    pub fn scrollback_len(&self) -> usize {
        self.core.primary.scrollback_len()
    }

    pub fn scrollback_line(&self, i: usize) -> Option<&[crate::screen::Cell]> {
        self.core.primary.scrollback_line(i)
    }

    /// 取走对查询序列（DA/DSR）的应答字节。
    pub fn take_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.core.replies)
    }
}

/// 屏幕与模式的持有者；实现解析事件处理器。
struct TermCore {
    primary: Screen,
    alt: Option<Screen>,
    scrollback_limit: usize,

    pen: Pen,
    last_printed: char,
    last_width: usize,

    title: String,
    icon_title: String,
    bell_count: u64,

    insert_mode: bool,
    newline_mode: bool,
    application_cursor_keys: bool,
    application_keypad: bool,
    bracketed_paste: bool,
    focus_reporting: bool,
    mouse_normal: bool,
    mouse_button: bool,
    mouse_any: bool,
    mouse_encoding: MouseEncoding,

    replies: Vec<u8>,
}

impl TermCore {
    fn new(cols: u16, rows: u16, scrollback_limit: usize) -> Self {
        Self {
            primary: Screen::new(cols, rows, scrollback_limit, false),
            alt: None,
            scrollback_limit,
            pen: Pen::default(),
            last_printed: ' ',
            last_width: 1,
            title: String::new(),
            icon_title: String::new(),
            bell_count: 0,
            insert_mode: false,
            newline_mode: false,
            application_cursor_keys: false,
            application_keypad: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_normal: false,
            mouse_button: false,
            mouse_any: false,
            mouse_encoding: MouseEncoding::Legacy,
            replies: Vec::new(),
        }
    }

    fn active(&self) -> &Screen {
        self.alt.as_ref().unwrap_or(&self.primary)
    }

    fn active_mut(&mut self) -> &mut Screen {
        match self.alt.as_mut() {
            Some(a) => a,
            None => &mut self.primary,
        }
    }

    fn screen_view(&self) -> ScreenView {
        let s = self.active();
        let mut cells = Vec::with_capacity(s.cols() as usize * s.rows() as usize);
        for y in 0..s.rows() {
            for x in 0..s.cols() {
                cells.push(s.cell(x, y).clone());
            }
        }
        ScreenView {
            cols: s.cols(),
            rows: s.rows(),
            cells,
            cursor: s.cursor(),
            damage: s.damage_rows(),
            is_alt: s.is_alt(),
            scrollback_len: s.scrollback_len(),
        }
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.primary.resize(cols, rows);
        if let Some(a) = self.alt.as_mut() {
            a.resize(cols, rows);
        }
    }

    fn mouse_mode(&self) -> MouseMode {
        if self.mouse_any {
            MouseMode::Any
        } else if self.mouse_button {
            MouseMode::Button
        } else if self.mouse_normal {
            MouseMode::Normal
        } else {
            MouseMode::None
        }
    }

    fn param(&self, groups: &[Vec<u32>], i: usize) -> u32 {
        groups.get(i).and_then(|g| g.first().copied()).unwrap_or(0)
    }

    /// n 默认 1（0 视作默认）。
    fn param_nz(&self, groups: &[Vec<u32>], i: usize) -> u32 {
        let v = self.param(groups, i);
        if v == 0 {
            1
        } else {
            v
        }
    }

    fn reply(&mut self, s: &str) {
        self.replies.extend_from_slice(s.as_bytes());
    }

    // ---------- 光标移动（带原点/边距约束） ----------

    fn cursor_y_limit(&self) -> u16 {
        let s = self.active();
        if s.origin_mode() {
            s.margins().1
        } else {
            s.rows() - 1
        }
    }

    fn cursor_y_origin(&self) -> u16 {
        let s = self.active();
        if s.origin_mode() {
            s.margins().0
        } else {
            0
        }
    }

    fn move_up(&mut self, n: u32) {
        let n = n.min(u32::from(self.active().rows()));
        let floor = self.cursor_y_origin();
        let c = self.active().cursor();
        let y = c.y.saturating_sub(n as u16).max(floor);
        self.active_mut().move_to(c.x, y);
    }

    fn move_down(&mut self, n: u32) {
        let n = n.min(u32::from(self.active().rows()));
        let ceil = self.cursor_y_limit();
        let c = self.active().cursor();
        let y = (c.y + n as u16).min(ceil);
        self.active_mut().move_to(c.x, y);
    }

    fn move_right(&mut self, n: u32) {
        let n = n.min(u32::from(self.active().cols()));
        let c = self.active().cursor();
        let x = (c.x + n as u16).min(self.active().cols() - 1);
        self.active_mut().move_to(x, c.y);
    }

    fn move_left(&mut self, n: u32) {
        let n = n.min(u32::from(self.active().cols()));
        let c = self.active().cursor();
        let x = c.x.saturating_sub(n as u16);
        self.active_mut().move_to(x, c.y);
    }

    /// CUP/HVP：参数 1-based；0 视作 1。
    fn cup(&mut self, groups: &[Vec<u32>]) {
        let row = self.param_nz(groups, 0);
        let col = self.param_nz(groups, 1);
        let top = self.cursor_y_origin();
        let bottom = self.cursor_y_limit();
        let y = (top + (row - 1) as u16).min(bottom);
        let x = ((col - 1) as u16).min(self.active().cols() - 1);
        self.active_mut().move_to(x, y);
    }

    fn cha(&mut self, groups: &[Vec<u32>]) {
        let col = self.param_nz(groups, 0);
        let x = ((col - 1) as u16).min(self.active().cols() - 1);
        let y = self.active().cursor().y;
        self.active_mut().move_to(x, y);
    }

    fn vpa(&mut self, groups: &[Vec<u32>]) {
        let row = self.param_nz(groups, 0);
        let top = self.cursor_y_origin();
        let bottom = self.cursor_y_limit();
        let y = (top + (row - 1) as u16).min(bottom);
        let x = self.active().cursor().x;
        self.active_mut().move_to(x, y);
    }

    fn do_sgr(&mut self, groups: &[Vec<u32>]) {
        if groups.is_empty() {
            self.pen = Pen::default();
            return;
        }
        let mut i = 0;
        while i < groups.len() {
            // 组内子参数（colon 形式）或跨组（semicolon 形式）
            let g = &groups[i];
            let head = g.first().copied().unwrap_or(0);
            match head {
                0 => self.pen = Pen::default(),
                1 => self.pen.attrs.insert(Attrs::BOLD),
                2 => self.pen.attrs.insert(Attrs::FAINT),
                3 => self.pen.attrs.insert(Attrs::ITALIC),
                4 => self.pen.attrs.insert(Attrs::UNDERLINE),
                5 | 6 => self.pen.attrs.insert(Attrs::BLINK),
                7 => self.pen.attrs.insert(Attrs::INVERSE),
                8 => self.pen.attrs.insert(Attrs::HIDDEN),
                9 => self.pen.attrs.insert(Attrs::STRIKE),
                21 => self.pen.attrs.insert(Attrs::UNDERLINE),
                22 => {
                    self.pen.attrs.remove(Attrs::BOLD);
                    self.pen.attrs.remove(Attrs::FAINT);
                }
                23 => self.pen.attrs.remove(Attrs::ITALIC),
                24 => self.pen.attrs.remove(Attrs::UNDERLINE),
                25 => self.pen.attrs.remove(Attrs::BLINK),
                27 => self.pen.attrs.remove(Attrs::INVERSE),
                28 => self.pen.attrs.remove(Attrs::HIDDEN),
                29 => self.pen.attrs.remove(Attrs::STRIKE),
                30..=37 => self.pen.fg = Color::Indexed((head - 30) as u8),
                39 => self.pen.fg = Color::Default,
                40..=47 => self.pen.bg = Color::Indexed((head - 40) as u8),
                49 => self.pen.bg = Color::Default,
                90..=97 => self.pen.fg = Color::Indexed((head - 90 + 8) as u8),
                100..=107 => self.pen.bg = Color::Indexed((head - 100 + 8) as u8),
                38 | 48 => {
                    let is_fg = head == 38;
                    // colon 形式：同一组携带后续值；semicolon 形式：后续组
                    let vals: Vec<u32> = if g.len() > 1 {
                        g[1..].to_vec()
                    } else {
                        let mut v = Vec::new();
                        let mut j = i + 1;
                        while j < groups.len() && v.len() < 4 {
                            v.push(groups[j].first().copied().unwrap_or(0));
                            j += 1;
                        }
                        // 跨组参数被消费：下一轮从 j 开始（i = j - 1，随后 i += 1）
                        i = j.saturating_sub(1);
                        v
                    };
                    let color = match vals.first().copied().unwrap_or(0) {
                        5 => vals.get(1).map(|&n| Color::Indexed(n.min(255) as u8)),
                        2 => {
                            // colon 形式可能带 colorspace（38:2::r:g:b -> [2, 0, r, g, b]）
                            let (r, g_idx, b) = if vals.len() >= 5 {
                                (vals[2], vals[3], vals[4])
                            } else {
                                (vals.get(1).copied().unwrap_or(0),
                                 vals.get(2).copied().unwrap_or(0),
                                 vals.get(3).copied().unwrap_or(0))
                            };
                            Some(Color::Rgb(r.min(255) as u8, g_idx.min(255) as u8, b.min(255) as u8))
                        }
                        _ => None,
                    };
                    if let Some(c) = color {
                        if is_fg {
                            self.pen.fg = c;
                        } else {
                            self.pen.bg = c;
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn do_mode(&mut self, groups: &[Vec<u32>], private: Option<char>, enable: bool) {
        if private != Some('?') {
            for g in groups {
                match g.first().copied().unwrap_or(0) {
                    4 => self.insert_mode = enable,
                    20 => self.newline_mode = enable,
                    _ => {}
                }
            }
            return;
        }
        for g in groups {
            match g.first().copied().unwrap_or(0) {
                1 => self.application_cursor_keys = enable,
                6 => {
                    // DECOM：原点模式；切换时回原点
                    let s = self.active_mut();
                    s.set_origin_mode(enable);
                    let (top, _) = s.margins();
                    s.move_to(0, if enable { top } else { 0 });
                }
                7 => self.active_mut().set_autowrap(enable),
                12 => {} // 光标闪烁（存储意义不大，忽略）
                25 => self.active_mut().set_cursor_visible(enable),
                47 | 1047 => {
                    if enable {
                        self.enter_alt(true);
                    } else {
                        self.leave_alt(true);
                    }
                }
                1000 => self.mouse_normal = enable,
                1002 => self.mouse_button = enable,
                1003 => self.mouse_any = enable,
                1004 => self.focus_reporting = enable,
                1006 => {
                    self.mouse_encoding = if enable { MouseEncoding::Sgr } else { MouseEncoding::Legacy }
                }
                1048 => {
                    if enable {
                        let pen = self.pen;
                        self.active_mut().save_cursor(&pen);
                    } else {
                        let mut pen = self.pen;
                        self.active_mut().restore_cursor(&mut pen);
                        self.pen = pen;
                    }
                }
                1049 => {
                    if enable {
                        let pen = self.pen;
                        self.primary.save_cursor(&pen);
                        self.enter_alt(true);
                    } else {
                        self.leave_alt(true);
                        let mut pen = self.pen;
                        self.primary.restore_cursor(&mut pen);
                        self.pen = pen;
                    }
                }
                2004 => self.bracketed_paste = enable,
                _ => {}
            }
        }
    }

    fn enter_alt(&mut self, clear: bool) {
        if self.alt.is_some() {
            return;
        }
        let (cols, rows) = (self.primary.cols(), self.primary.rows());
        let mut alt = Screen::new(cols, rows, 0, true);
        if !clear {
            alt.clone_from(&self.primary);
            alt.clear_damage();
        }
        self.alt = Some(alt);
    }

    fn leave_alt(&mut self, clear: bool) {
        if let Some(mut alt) = self.alt.take() {
            if clear {
                let pen = Pen::default();
                alt.erase_in_display(2, &pen);
            }
        }
    }

    fn reset_all(&mut self) {
        let (cols, rows) = (self.primary.cols(), self.primary.rows());
        self.primary = Screen::new(cols, rows, self.scrollback_limit, false);
        self.alt = None;
        self.pen = Pen::default();
        self.insert_mode = false;
        self.newline_mode = false;
        self.application_cursor_keys = false;
        self.application_keypad = false;
        self.bracketed_paste = false;
        self.focus_reporting = false;
        self.mouse_normal = false;
        self.mouse_button = false;
        self.mouse_any = false;
        self.mouse_encoding = MouseEncoding::Legacy;
        self.last_printed = ' ';
        self.last_width = 1;
        // 标题与 bell 计数不因 RIS 清除
    }
}

impl Handler for TermCore {
    fn print(&mut self, c: char) {
        let w = char_width(c);
        let insert = self.insert_mode;
        let pen = self.pen;
        if w == 1 {
            self.last_printed = c;
            self.last_width = 1;
        } else if w == 2 {
            self.last_printed = c;
            self.last_width = 2;
        }
        self.active_mut().put_char(c, w, &pen, insert);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x07 => self.bell_count += 1, // BEL
            0x08 => self.active_mut().backspace(),
            0x09 => self.active_mut().next_tab(),
            0x0a | 0x0b | 0x0c => {
                // LF / VT / FF
                let pen = self.pen;
                self.active_mut().linefeed(&pen);
                if self.newline_mode {
                    self.active_mut().carriage_return();
                }
            }
            0x0d => self.active_mut().carriage_return(),
            0x0e | 0x0f => {} // SO/SI 字符集切换：忽略
            _ => {}
        }
    }

    fn csi_dispatch(
        &mut self,
        groups: &[Vec<u32>],
        private: Option<char>,
        intermediates: &[u8],
        final_byte: u8,
    ) {
        match final_byte {
            b'@' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().insert_chars(n as u16, &pen);
            }
            b'A' => {
                let n = self.param_nz(groups, 0);
                self.move_up(n);
            }
            b'B' | b'e' => {
                let n = self.param_nz(groups, 0);
                self.move_down(n);
            }
            b'C' | b'a' => {
                let n = self.param_nz(groups, 0);
                self.move_right(n);
            }
            b'D' => {
                let n = self.param_nz(groups, 0);
                self.move_left(n);
            }
            b'E' => {
                let n = self.param_nz(groups, 0);
                self.move_down(n);
                self.active_mut().carriage_return();
            }
            b'F' => {
                let n = self.param_nz(groups, 0);
                self.move_up(n);
                self.active_mut().carriage_return();
            }
            b'G' | b'`' => self.cha(groups),
            b'H' | b'f' => self.cup(groups),
            b'I' => {
                let n = self.param_nz(groups, 0);
                for _ in 0..n {
                    self.active_mut().next_tab();
                }
            }
            b'J' => {
                let mode = self.param(groups, 0);
                let pen = self.pen;
                self.active_mut().erase_in_display(mode, &pen);
            }
            b'K' => {
                let mode = self.param(groups, 0);
                let pen = self.pen;
                self.active_mut().erase_in_line(mode, &pen);
            }
            b'L' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().insert_lines(n as u16, &pen);
            }
            b'M' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().delete_lines(n as u16, &pen);
            }
            b'P' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().delete_chars(n as u16, &pen);
            }
            b'S' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().scroll_up(n as u16, &pen);
            }
            b'T' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().scroll_down(n as u16, &pen);
            }
            b'X' => {
                let n = self.param_nz(groups, 0);
                let pen = self.pen;
                self.active_mut().erase_chars(n as u16, &pen);
            }
            b'Z' => {
                let n = self.param_nz(groups, 0);
                for _ in 0..n {
                    self.active_mut().prev_tab();
                }
            }
            b'b' => {
                let n = self.param_nz(groups, 0);
                let (c, w) = (self.last_printed, self.last_width);
                let pen = self.pen;
                let insert = self.insert_mode;
                self.active_mut().repeat_last(c, w, n, &pen, insert);
            }
            b'c' => {
                // DA1（CSI c）→ ?1;2c；DA2（CSI > c）→ >0;95;0c
                match private {
                    Some('>') => self.reply("\u{1b}[>0;95;0c"),
                    _ => self.reply("\u{1b}[?1;2c"),
                }
            }
            b'd' => self.vpa(groups),
            b'g' => match self.param(groups, 0) {
                0 => self.active_mut().clear_tab_at_cursor(),
                3 => self.active_mut().clear_all_tabs(),
                _ => {}
            },
            b'h' => self.do_mode(groups, private, true),
            b'l' => self.do_mode(groups, private, false),
            b'm' => self.do_sgr(groups),
            b'n' => {
                if private.is_none() {
                    match self.param(groups, 0) {
                        5 => self.reply("\u{1b}[0n"),
                        6 => {
                            let c = self.active().cursor();
                            let (top, _) = self.active().margins();
                            let base = if self.active().origin_mode() { top } else { 0 };
                            let y = c.y.saturating_sub(base) + 1;
                            self.reply(&format!("\u{1b}[{};{}R", y, c.x + 1));
                        }
                        _ => {}
                    }
                }
            }
            b'r' => {
                // DECSTBM
                let rows = self.active().rows();
                let top = if self.param(groups, 0) == 0 {
                    1
                } else {
                    self.param(groups, 0)
                };
                let bottom = if self.param(groups, 1) == 0 {
                    rows as u32
                } else {
                    self.param(groups, 1)
                };
                if top <= bottom && bottom <= rows as u32 {
                    self.active_mut().set_margins(top as u16 - 1, bottom as u16 - 1);
                } else {
                    self.active_mut().set_margins(0, rows - 1);
                }
                let y = self.cursor_y_origin();
                self.active_mut().move_to(0, y);
            }
            b's' => {
                let pen = self.pen;
                self.active_mut().save_cursor(&pen);
            }
            b'u' => {
                let mut pen = self.pen;
                self.active_mut().restore_cursor(&mut pen);
                self.pen = pen;
            }
            b'p' if intermediates.len() == 1 && intermediates[0] == b'!' => {
                self.reset_all() // 软复位
            }
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], final_byte: u8) {
        match (intermediates, final_byte) {
            (&[], b'7') => {
                let pen = self.pen;
                self.active_mut().save_cursor(&pen);
            }
            (&[], b'8') => {
                let mut pen = self.pen;
                self.active_mut().restore_cursor(&mut pen);
                self.pen = pen;
            }
            (&[], b'D') => {
                // IND
                let pen = self.pen;
                self.active_mut().linefeed(&pen);
            }
            (&[], b'E') => {
                // NEL
                let pen = self.pen;
                self.active_mut().linefeed(&pen);
                self.active_mut().carriage_return();
            }
            (&[], b'H') => self.active_mut().set_tab_at_cursor(),
            (&[], b'M') => {
                // RI
                let pen = self.pen;
                self.active_mut().reverse_index(&pen);
            }
            (&[], b'c') => self.reset_all(), // RIS
            (&[], b'=') => self.application_keypad = true,
            (&[], b'>') => self.application_keypad = false,
            (&[], b'Z') => self.reply("\u{1b}[?1;2c"), // DECID
            (&[b'#'], b'8') => {
                // DECALN：全屏填 E
                let pen = self.pen;
                let rows = self.active().rows();
                for y in 0..rows {
                    self.active_mut().move_to(0, y);
                    let cols = self.active().cols();
                    for _ in 0..cols {
                        self.active_mut().put_char('E', 1, &pen, false);
                    }
                }
                self.active_mut().move_to(0, 0);
            }
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, payload: &str) {
        let (code, rest) = match payload.split_once(';') {
            Some((c, r)) => (c, r),
            None => (payload, ""),
        };
        match code {
            "0" => {
                self.title = rest.to_string();
                self.icon_title = rest.to_string();
            }
            "1" => self.icon_title = rest.to_string(),
            "2" => self.title = rest.to_string(),
            _ => {}
        }
        if self.title.len() > 4096 {
            self.title.truncate(4096);
        }
    }

    fn dcs_dispatch(&mut self, _payload: &str) {
        // DECRQSS 等暂不支持；消费即可
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term() -> Terminal {
        Terminal::new(20, 5)
    }

    fn feed_str(t: &mut Terminal, s: &str) {
        t.feed(s.as_bytes());
    }

    #[test]
    fn cup_and_print() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}[3;5Hhi");
        let v = t.get_screen();
        assert_eq!(v.cell(4, 2).unwrap().ch, 'h');
        assert_eq!(v.cell(5, 2).unwrap().ch, 'i');
        assert_eq!(v.cursor.x, 6);
        assert_eq!(v.cursor.y, 2);
    }

    #[test]
    fn sgr_colors_and_attrs() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}[1;31mR\u{1b}[0m\u{1b}[38;2;10;20;30mX\u{1b}[48;5;196mY");
        let v = t.get_screen();
        let r = v.cell(0, 0).unwrap();
        assert_eq!(r.fg, Color::Indexed(1));
        assert!(r.attrs.contains(Attrs::BOLD));
        let x = v.cell(1, 0).unwrap();
        assert_eq!(x.fg, Color::Rgb(10, 20, 30));
        assert!(!x.attrs.contains(Attrs::BOLD));
        let y = v.cell(2, 0).unwrap();
        assert_eq!(y.bg, Color::Indexed(196));
    }

    #[test]
    fn sgr_colon_form_truecolor() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}[38:2::1:2:3mZ");
        let v = t.get_screen();
        assert_eq!(v.cell(0, 0).unwrap().fg, Color::Rgb(1, 2, 3));
    }

    #[test]
    fn erase_display_clears_and_marks_damage() {
        let mut t = term();
        feed_str(&mut t, "hello\u{1b}[2J\u{1b}[H");
        let v = t.get_screen();
        assert_eq!(v.line_text(0), "");
        assert!(v.damage.contains(&0));
    }

    #[test]
    fn scroll_and_scrollback() {
        let mut t = Terminal::with_options(10, 3, TerminalOptions { scrollback_limit: 50 });
        for i in 0..6 {
            feed_str(&mut t, &format!("line{}\r\n", i));
        }
        // 3 行屏幕 + 6 行输入（每行带换行）：line0..line3 入回滚，可见 line4/line5
        assert_eq!(t.scrollback_len(), 4);
        assert_eq!(t.get_screen().line_text(0), "line4");
        assert_eq!(t.get_screen().line_text(1), "line5");
        assert_eq!(t.scrollback_line(0).unwrap()[0].ch, 'l');
    }

    #[test]
    fn alt_screen_enter_and_leave() {
        let mut t = term();
        feed_str(&mut t, "primary");
        feed_str(&mut t, "\u{1b}[?1049h");
        assert!(t.is_alt_screen());
        assert_eq!(t.get_screen().line_text(0), "");
        feed_str(&mut t, "alt-text");
        assert_eq!(t.get_screen().line_text(0), "alt-text");
        feed_str(&mut t, "\u{1b}[?1049l");
        assert!(!t.is_alt_screen());
        assert_eq!(t.get_screen().line_text(0), "primary");
    }

    #[test]
    fn mouse_and_paste_modes() {
        let mut t = term();
        assert_eq!(t.mouse_mode(), MouseMode::None);
        feed_str(&mut t, "\u{1b}[?1000h\u{1b}[?1006h\u{1b}[?2004h\u{1b}[?1003h");
        assert_eq!(t.mouse_mode(), MouseMode::Any);
        assert_eq!(t.mouse_encoding(), MouseEncoding::Sgr);
        assert!(t.bracketed_paste());
        feed_str(&mut t, "\u{1b}[?1000l\u{1b}[?1003l\u{1b}[?1006l\u{1b}[?2004l");
        assert_eq!(t.mouse_mode(), MouseMode::None);
        assert_eq!(t.mouse_encoding(), MouseEncoding::Legacy);
        assert!(!t.bracketed_paste());
    }

    #[test]
    fn osc_title_bel_and_st() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}]0;hello\u{07}");
        assert_eq!(t.title(), "hello");
        feed_str(&mut t, "\u{1b}]2;world\u{1b}\\");
        assert_eq!(t.title(), "world");
        assert_eq!(t.icon_title(), "hello");
    }

    #[test]
    fn da_and_dsr_replies() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}[c\u{1b}[5n");
        assert_eq!(t.take_replies(), "\u{1b}[?1;2c\u{1b}[0n".as_bytes());
        feed_str(&mut t, "\u{1b}[4;6H\u{1b}[6n");
        assert_eq!(t.take_replies(), "\u{1b}[4;6R".as_bytes());
    }

    #[test]
    fn utf8_split_across_feeds() {
        let mut t = term();
        t.feed("h\u{4e2d}".as_bytes()[..3].as_ref()); // 'h' + 中的前两字节
        t.feed("\u{4e2d}".as_bytes()[2..].as_ref());
        assert_eq!(t.get_screen().line_text(0), "h中");
    }

    #[test]
    fn decaln_fills_with_e() {
        let mut t = term();
        feed_str(&mut t, "\u{1b}#8");
        let v = t.get_screen();
        assert_eq!(v.line_text(0), "EEEEEEEEEEEEEEEEEEEE");
        feed_str(&mut t, "\u{1b}c"); // RIS 复位
        assert_eq!(t.get_screen().line_text(0), "");
    }

    #[test]
    fn wide_char_via_terminal() {
        let mut t = term();
        feed_str(&mut t, "中");
        let v = t.get_screen();
        assert_eq!(v.cell(0, 0).unwrap().ch, '中');
        assert!(v.cell(1, 0).unwrap().is_continuation());
        assert_eq!(v.cursor.x, 2);
    }

    #[test]
    fn rep_repeats_last_char() {
        let mut t = term();
        feed_str(&mut t, "a\u{1b}[5b");
        assert_eq!(t.get_screen().line_text(0), "aaaaaa");
    }

    #[test]
    fn scroll_region_and_reverse_index() {
        let mut t = Terminal::with_options(10, 5, TerminalOptions { scrollback_limit: 0 });
        feed_str(&mut t, "\u{1b}[2;4r"); // 滚动区 2..4
        feed_str(&mut t, "\u{1b}[2;1H");
        for _ in 0..4 {
            feed_str(&mut t, "x\r\n");
        }
        let v = t.get_screen();
        assert_eq!(v.line_text(0), ""); // 区外顶行不变
        assert_eq!(v.line_text(4), "");
    }

    #[test]
    fn insert_mode_shifts() {
        let mut t = term();
        feed_str(&mut t, "abcd\u{1b}[1;2H\u{1b}[4hX");
        assert_eq!(t.get_screen().line_text(0), "aXbcd");
    }

    #[test]
    fn resize_keeps_content() {
        let mut t = term();
        feed_str(&mut t, "hello");
        t.resize(10, 3);
        assert_eq!(t.get_screen().line_text(0), "hello");
        t.resize(3, 3);
        assert_eq!(t.get_screen().line_text(0), "hel");
    }

    #[test]
    fn cursor_visibility_mode() {
        let mut t = term();
        assert!(t.get_screen().cursor.visible);
        feed_str(&mut t, "\u{1b}[?25l");
        assert!(!t.get_screen().cursor.visible);
        feed_str(&mut t, "\u{1b}[?25h");
        assert!(t.get_screen().cursor.visible);
    }

    #[test]
    fn newline_mode_lf_does_crlf() {
        let mut t = term();
        feed_str(&mut t, "ab\u{1b}[20h\nc");
        assert_eq!(t.get_screen().line_text(1), "c");
    }

    #[test]
    fn origin_mode_cup_relative_to_margins() {
        let mut t = Terminal::with_options(10, 6, TerminalOptions::default());
        feed_str(&mut t, "\u{1b}[3;5r"); // 边距 行3..5
        feed_str(&mut t, "\u{1b}[?6h"); // origin on -> 回到边距顶部
        assert_eq!(t.get_screen().cursor.y, 2);
        feed_str(&mut t, "\u{1b}[2;1H"); // 相对第2行 = 绝对第4行
        assert_eq!(t.get_screen().cursor.y, 3);
    }

    #[test]
    fn bell_count() {
        let mut t = term();
        feed_str(&mut t, "\u{07}\u{07}");
        assert_eq!(t.bell_count(), 2);
    }
}
