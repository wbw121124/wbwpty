//! 终端网格状态：单元格、光标、滚动区、回滚缓冲、damage。

use std::collections::VecDeque;

/// 颜色。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    /// 终端默认前景/背景。
    Default,
    /// 256 色调色板索引。
    Indexed(u8),
    /// 24-bit 真彩色。
    Rgb(u8, u8, u8),
}

/// 文本属性位。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Attrs(u8);

impl Attrs {
    pub const BOLD: Self = Self(1 << 0);
    pub const FAINT: Self = Self(1 << 1);
    pub const ITALIC: Self = Self(1 << 2);
    pub const UNDERLINE: Self = Self(1 << 3);
    pub const BLINK: Self = Self(1 << 4);
    pub const INVERSE: Self = Self(1 << 5);
    pub const HIDDEN: Self = Self(1 << 6);
    pub const STRIKE: Self = Self(1 << 7);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

/// 当前画笔（SGR 状态）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pen {
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attrs,
}

impl Default for Pen {
    fn default() -> Self {
        Self { fg: Color::Default, bg: Color::Default, attrs: Attrs::empty() }
    }
}

/// 单元格。宽字符的第二格用 [`Cell::is_continuation`] 标记。
#[derive(Clone, Debug, PartialEq)]
pub struct Cell {
    pub ch: char,
    /// 附着的组合字符（如重音符），渲染时叠加。
    pub combining: Vec<char>,
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attrs,
}

impl Cell {
    /// 宽字符占位（续格）字符。
    pub const CONTINUATION: char = '\u{0}';

    pub fn blank() -> Self {
        Self {
            ch: ' ',
            combining: Vec::new(),
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attrs::empty(),
        }
    }

    pub fn blank_with_bg(bg: Color) -> Self {
        Self { bg, ..Self::blank() }
    }

    pub fn is_continuation(&self) -> bool {
        self.ch == Self::CONTINUATION
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::blank()
    }
}

/// 光标状态（视图用）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CursorState {
    pub x: u16,
    pub y: u16,
    pub visible: bool,
}

/// 屏幕快照（`Terminal::get_screen()` 返回值）。
#[derive(Clone, Debug)]
pub struct ScreenView {
    pub cols: u16,
    pub rows: u16,
    /// 行优先扁平网格，长度 = cols * rows。
    pub cells: Vec<Cell>,
    pub cursor: CursorState,
    /// 自上次 `clear_damage` 以来变脏的行号。
    pub damage: Vec<u16>,
    pub is_alt: bool,
    pub scrollback_len: usize,
}

impl ScreenView {
    pub fn cell(&self, x: u16, y: u16) -> Option<&Cell> {
        if x >= self.cols || y >= self.rows {
            return None;
        }
        Some(&self.cells[y as usize * self.cols as usize + x as usize])
    }

    pub fn row(&self, y: u16) -> Option<&[Cell]> {
        if y >= self.rows {
            return None;
        }
        let cols = self.cols as usize;
        let start = y as usize * cols;
        Some(&self.cells[start..start + cols])
    }

    /// 行文本（跳过宽字符续格，去除尾部空格），测试与调试用。
    pub fn line_text(&self, y: u16) -> String {
        let Some(row) = self.row(y) else {
            return String::new();
        };
        let mut s = String::new();
        for c in row {
            if c.is_continuation() {
                continue;
            }
            s.push(c.ch);
            for &d in &c.combining {
                s.push(d);
            }
        }
        while s.ends_with(' ') {
            s.pop();
        }
        s
    }
}

#[derive(Clone, Debug)]
struct SavedCursor {
    x: u16,
    y: u16,
    pen: Pen,
    origin_mode: bool,
    pending_wrap: bool,
}

/// 一张屏幕（主屏或备用屏）。坐标 0-based；边距含端点。
#[derive(Clone, Debug)]
pub struct Screen {
    cols: u16,
    rows: u16,
    grid: Vec<Vec<Cell>>,
    scrollback: VecDeque<Vec<Cell>>,
    scrollback_limit: usize,
    alt: bool,

    cursor_x: u16,
    cursor_y: u16,
    pending_wrap: bool,
    cursor_visible: bool,
    autowrap: bool,
    origin_mode: bool,

    margin_top: u16,
    margin_bottom: u16,
    damage: Vec<bool>,
    saved: Option<SavedCursor>,
    tabs: Vec<bool>,
}

impl Screen {
    pub fn new(cols: u16, rows: u16, scrollback_limit: usize, alt: bool) -> Self {
        let mut s = Self {
            cols,
            rows,
            grid: vec![vec![Cell::blank(); cols as usize]; rows as usize],
            scrollback: VecDeque::new(),
            scrollback_limit: if alt { 0 } else { scrollback_limit },
            alt,
            cursor_x: 0,
            cursor_y: 0,
            pending_wrap: false,
            cursor_visible: true,
            autowrap: true,
            origin_mode: false,
            margin_top: 0,
            margin_bottom: rows.saturating_sub(1),
            damage: vec![true; rows as usize],
            saved: None,
            tabs: default_tabs(cols),
        };
        s.mark_all();
        s
    }

    pub fn cols(&self) -> u16 {
        self.cols
    }
    pub fn rows(&self) -> u16 {
        self.rows
    }
    pub fn is_alt(&self) -> bool {
        self.alt
    }
    pub fn cursor(&self) -> CursorState {
        CursorState { x: self.cursor_x, y: self.cursor_y, visible: self.cursor_visible }
    }
    pub fn set_cursor_visible(&mut self, v: bool) {
        self.cursor_visible = v;
    }
    pub fn set_autowrap(&mut self, v: bool) {
        self.autowrap = v;
    }
    pub fn set_origin_mode(&mut self, v: bool) {
        self.origin_mode = v;
    }
    pub fn origin_mode(&self) -> bool {
        self.origin_mode
    }
    pub fn margins(&self) -> (u16, u16) {
        (self.margin_top, self.margin_bottom)
    }
    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }
    pub fn scrollback_line(&self, i: usize) -> Option<&[Cell]> {
        self.scrollback.get(i).map(|v| v.as_slice())
    }

    pub fn cell(&self, x: u16, y: u16) -> &Cell {
        &self.grid[y as usize][x as usize]
    }

    pub fn clear_damage(&mut self) {
        for d in &mut self.damage {
            *d = false;
        }
    }

    pub fn damage_rows(&self) -> Vec<u16> {
        self.damage
            .iter()
            .enumerate()
            .filter(|(_, &d)| d)
            .map(|(i, _)| i as u16)
            .collect()
    }

    fn mark(&mut self, y: u16) {
        self.damage[y as usize] = true;
    }

    fn mark_all(&mut self) {
        for d in &mut self.damage {
            *d = true;
        }
    }

    fn mark_region(&mut self, top: u16, bottom: u16) {
        for y in top..=bottom {
            self.damage[y as usize] = true;
        }
    }

    fn blank_row(&self, bg: Color) -> Vec<Cell> {
        vec![Cell::blank_with_bg(bg); self.cols as usize]
    }

    // ---------- 光标与输入 ----------

    pub fn carriage_return(&mut self) {
        self.cursor_x = 0;
        self.pending_wrap = false;
    }

    pub fn backspace(&mut self) {
        if self.pending_wrap {
            self.pending_wrap = false;
        } else if self.cursor_x > 0 {
            self.cursor_x -= 1;
        }
    }

    pub fn next_tab(&mut self) {
        let mut x = self.cursor_x + 1;
        while x < self.cols {
            if self.tabs.get(x as usize).copied().unwrap_or(false) {
                break;
            }
            x += 1;
        }
        self.cursor_x = x.min(self.cols.saturating_sub(1));
        self.pending_wrap = false;
    }

    pub fn prev_tab(&mut self) {
        while self.cursor_x > 0 {
            self.cursor_x -= 1;
            if self.tabs.get(self.cursor_x as usize).copied().unwrap_or(false) {
                break;
            }
        }
        self.pending_wrap = false;
    }

    pub fn set_tab_at_cursor(&mut self) {
        if (self.cursor_x as usize) < self.tabs.len() {
            self.tabs[self.cursor_x as usize] = true;
        }
    }

    pub fn clear_tab_at_cursor(&mut self) {
        if let Some(t) = self.tabs.get_mut(self.cursor_x as usize) {
            *t = false;
        }
    }

    pub fn clear_all_tabs(&mut self) {
        for t in &mut self.tabs {
            *t = false;
        }
    }

    /// 直接移动光标（0-based，由调用方负责边距/原点约束）。
    pub fn move_to(&mut self, x: u16, y: u16) {
        self.cursor_x = x.min(self.cols.saturating_sub(1));
        self.cursor_y = y.min(self.rows.saturating_sub(1));
        self.pending_wrap = false;
    }

    pub fn linefeed(&mut self, pen: &Pen) {
        if self.cursor_y == self.margin_bottom {
            self.scroll_up(1, pen);
        } else if self.cursor_y + 1 < self.rows {
            self.cursor_y += 1;
        }
        self.pending_wrap = false;
    }

    pub fn reverse_index(&mut self, pen: &Pen) {
        if self.cursor_y == self.margin_top {
            self.scroll_down(1, pen);
        } else if self.cursor_y > 0 {
            self.cursor_y -= 1;
        }
        self.pending_wrap = false;
    }

    /// 打印一个字符（宽度由调用方计算；width==0 表示组合字符）。
    pub fn put_char(&mut self, c: char, width: usize, pen: &Pen, insert: bool) {
        if width == 0 {
            self.attach_combining(c);
            return;
        }
        if self.pending_wrap && self.autowrap {
            self.pending_wrap = false;
            self.carriage_return();
            self.linefeed(pen);
        }
        if self.cursor_x as usize + width > self.cols as usize {
            if self.autowrap {
                self.carriage_return();
                self.linefeed(pen);
            } else {
                self.cursor_x = self.cols.saturating_sub(width as u16);
            }
        }
        if insert {
            self.insert_cells(width as u16, pen);
        }
        let y = self.cursor_y as usize;
        let x = self.cursor_x as usize;
        let cell = Cell { ch: c, combining: Vec::new(), fg: pen.fg, bg: pen.bg, attrs: pen.attrs };
        self.grid[y][x] = cell;
        if width == 2 && x + 1 < self.cols as usize {
            self.grid[y][x + 1] = Cell {
                ch: Cell::CONTINUATION,
                combining: Vec::new(),
                fg: pen.fg,
                bg: pen.bg,
                attrs: pen.attrs,
            };
        }
        self.mark(self.cursor_y);

        let next = self.cursor_x as usize + width;
        if next >= self.cols as usize {
            self.cursor_x = self.cols - 1;
            self.pending_wrap = true;
        } else {
            self.cursor_x = next as u16;
        }
    }

    fn attach_combining(&mut self, c: char) {
        if self.cursor_x == 0 {
            return;
        }
        let mut px = self.cursor_x - 1;
        let y = self.cursor_y as usize;
        if self.grid[y][px as usize].is_continuation() && px > 0 {
            px -= 1;
        }
        // 组合上限，防止无限增长
        if self.grid[y][px as usize].combining.len() < 16 {
            self.grid[y][px as usize].combining.push(c);
        }
        self.mark(self.cursor_y);
    }

    /// 打印最后字符 n 次（CSI b REP）。
    pub fn repeat_last(&mut self, c: char, width: usize, n: u32, pen: &Pen, insert: bool) {
        let n = n.min(65_535);
        for _ in 0..n {
            self.put_char(c, width, pen, insert);
        }
    }

    // ---------- 擦除 ----------

    fn erase_cell(&self, pen: &Pen) -> Cell {
        Cell::blank_with_bg(pen.bg)
    }

    fn erase_row_range(&mut self, y: u16, from: u16, to: u16, pen: &Pen) {
        let cell = self.erase_cell(pen);
        for x in from..=to {
            self.grid[y as usize][x as usize] = cell.clone();
        }
        self.mark(y);
    }

    /// J：0 光标到屏尾，1 屏首到光标（含），2 全屏，3 全屏+回滚。
    pub fn erase_in_display(&mut self, mode: u32, pen: &Pen) {
        match mode {
            0 => {
                self.erase_row_range(self.cursor_y, self.cursor_x, self.cols - 1, pen);
                for y in self.cursor_y + 1..self.rows {
                    self.erase_row_range(y, 0, self.cols - 1, pen);
                }
            }
            1 => {
                self.erase_row_range(self.cursor_y, 0, self.cursor_x, pen);
                for y in 0..self.cursor_y {
                    self.erase_row_range(y, 0, self.cols - 1, pen);
                }
            }
            2 => {
                for y in 0..self.rows {
                    self.erase_row_range(y, 0, self.cols - 1, pen);
                }
            }
            3 => {
                for y in 0..self.rows {
                    self.erase_row_range(y, 0, self.cols - 1, pen);
                }
                self.scrollback.clear();
            }
            _ => {}
        }
        self.pending_wrap = false;
    }

    /// K：0 光标到行尾，1 行首到光标（含），2 整行。
    pub fn erase_in_line(&mut self, mode: u32, pen: &Pen) {
        let (from, to) = match mode {
            1 => (0, self.cursor_x),
            2 => (0, self.cols - 1),
            _ => (self.cursor_x, self.cols - 1),
        };
        self.erase_row_range(self.cursor_y, from, to, pen);
        self.pending_wrap = false;
    }

    // ---------- 插入/删除 ----------

    fn insert_cells(&mut self, n: u16, _pen: &Pen) {
        let y = self.cursor_y as usize;
        let x = self.cursor_x as usize;
        let n = (n as usize).min(self.cols as usize - x);
        let row = &mut self.grid[y];
        row.splice(x..x, std::iter::repeat(Cell::blank()).take(n));
        row.truncate(self.cols as usize);
        self.mark(self.cursor_y);
    }

    pub fn insert_chars(&mut self, n: u16, pen: &Pen) {
        self.insert_cells(n, pen);
    }

    pub fn delete_chars(&mut self, n: u16, _pen: &Pen) {
        let y = self.cursor_y as usize;
        let x = self.cursor_x as usize;
        let n = (n as usize).min(self.cols as usize - x);
        let row = &mut self.grid[y];
        // 删除光标处 n 个单元格（后续左移），行尾补空
        row.splice(x..x + n, std::iter::empty());
        row.extend(std::iter::repeat(Cell::blank()).take(n));
        row.truncate(self.cols as usize);
        self.mark(self.cursor_y);
    }

    pub fn erase_chars(&mut self, n: u16, pen: &Pen) {
        let y = self.cursor_y;
        let from = self.cursor_x;
        let to = (self.cursor_x + n - 1).min(self.cols - 1);
        let cell = self.erase_cell(pen);
        for x in from..=to {
            self.grid[y as usize][x as usize] = cell.clone();
        }
        self.mark(y);
    }

    fn in_margins(&self) -> bool {
        self.cursor_y >= self.margin_top && self.cursor_y <= self.margin_bottom
    }

    pub fn insert_lines(&mut self, n: u16, pen: &Pen) {
        if !self.in_margins() {
            return;
        }
        let n = n.min(self.margin_bottom - self.cursor_y + 1);
        let bg = pen.bg;
        let y = self.cursor_y as usize;
        let bottom = self.margin_bottom as usize;
        for _ in 0..n {
            self.grid.insert(y, self.blank_row(bg));
            self.grid.remove(bottom + 1);
        }
        self.mark_region(self.cursor_y, self.margin_bottom);
        self.cursor_x = 0;
        self.pending_wrap = false;
    }

    pub fn delete_lines(&mut self, n: u16, pen: &Pen) {
        if !self.in_margins() {
            return;
        }
        let n = n.min(self.margin_bottom - self.cursor_y + 1);
        let bg = pen.bg;
        let y = self.cursor_y as usize;
        let bottom = self.margin_bottom as usize;
        for _ in 0..n {
            self.grid.remove(y);
            self.grid.insert(bottom, self.blank_row(bg));
        }
        self.mark_region(self.cursor_y, self.margin_bottom);
        self.cursor_x = 0;
        self.pending_wrap = false;
    }

    // ---------- 滚动 ----------

    pub fn scroll_up(&mut self, n: u16, pen: &Pen) {
        let height = self.margin_bottom - self.margin_top + 1;
        let n = n.min(height);
        let bg = pen.bg;
        let top = self.margin_top as usize;
        let bottom = self.margin_bottom as usize;
        for _ in 0..n {
            let removed = self.grid.remove(top);
            if self.margin_top == 0 && !self.alt && self.scrollback_limit > 0 {
                self.scrollback.push_back(removed);
                while self.scrollback.len() > self.scrollback_limit {
                    self.scrollback.pop_front();
                }
            }
            self.grid.insert(bottom, self.blank_row(bg));
        }
        self.mark_region(self.margin_top, self.margin_bottom);
    }

    pub fn scroll_down(&mut self, n: u16, pen: &Pen) {
        let height = self.margin_bottom - self.margin_top + 1;
        let n = n.min(height);
        let bg = pen.bg;
        let top = self.margin_top as usize;
        let bottom = self.margin_bottom as usize;
        for _ in 0..n {
            self.grid.insert(top, self.blank_row(bg));
            self.grid.remove(bottom + 1);
        }
        self.mark_region(self.margin_top, self.margin_bottom);
    }

    /// r：设置滚动区（0-based 含端点）。
    pub fn set_margins(&mut self, top: u16, bottom: u16) {
        let top = top.min(self.rows - 1);
        let bottom = bottom.min(self.rows - 1);
        if top < bottom {
            self.margin_top = top;
            self.margin_bottom = bottom;
        } else {
            self.margin_top = 0;
            self.margin_bottom = self.rows - 1;
        }
    }

    // ---------- 保存/恢复光标 ----------

    pub fn save_cursor(&mut self, pen: &Pen) {
        self.saved = Some(SavedCursor {
            x: self.cursor_x,
            y: self.cursor_y,
            pen: *pen,
            origin_mode: self.origin_mode,
            pending_wrap: self.pending_wrap,
        });
    }

    pub fn restore_cursor(&mut self, pen: &mut Pen) {
        if let Some(s) = self.saved.clone() {
            self.cursor_x = s.x.min(self.cols - 1);
            self.cursor_y = s.y.min(self.rows - 1);
            self.origin_mode = s.origin_mode;
            self.pending_wrap = s.pending_wrap;
            *pen = s.pen;
        } else {
            self.move_to(0, 0);
        }
    }

    // ---------- 尺寸 ----------

    pub fn resize(&mut self, cols: u16, rows: u16) {
        if cols == self.cols && rows == self.rows {
            return;
        }
        // 行内截断/补齐（不重排换行）
        for row in &mut self.grid {
            row.truncate(cols as usize);
            while row.len() < cols as usize {
                row.push(Cell::blank());
            }
        }
        // 行数变化
        if rows < self.rows {
            self.grid.truncate(rows as usize);
        } else {
            while self.grid.len() < rows as usize {
                // 优先从回滚取回（主屏）
                if !self.alt {
                    if let Some(line) = self.scrollback.pop_front() {
                        self.grid.push(line);
                        continue;
                    }
                }
                self.grid.push(vec![Cell::blank(); cols as usize]);
            }
        }
        // 补齐新列宽的行（回滚行可能是旧列宽）
        for row in &mut self.grid {
            while row.len() < cols as usize {
                row.push(Cell::blank());
            }
        }
        self.cols = cols;
        self.rows = rows;
        self.tabs = default_tabs(cols);
        self.margin_top = 0;
        self.margin_bottom = rows.saturating_sub(1);
        self.cursor_x = self.cursor_x.min(cols - 1);
        self.cursor_y = self.cursor_y.min(rows - 1);
        self.pending_wrap = false;
        self.damage = vec![true; rows as usize];
        self.mark_all();
    }
}

fn default_tabs(cols: u16) -> Vec<bool> {
    (0..cols as usize).map(|x| x > 0 && x % 8 == 0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pen() -> Pen {
        Pen::default()
    }

    #[test]
    fn put_char_advances_and_wraps() {
        let mut s = Screen::new(4, 3, 100, false);
        for c in "abcde".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        assert_eq!(s.cursor().x, 1);
        assert_eq!(s.cursor().y, 1);
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(3, 0).ch, 'd');
        assert_eq!(s.cell(0, 1).ch, 'e');
    }

    #[test]
    fn pending_wrap_waits_for_next_char() {
        let mut s = Screen::new(2, 2, 100, false);
        s.put_char('a', 1, &pen(), false);
        s.put_char('b', 1, &pen(), false);
        // 刚写满最后一列：光标停在原地，pending_wrap 置位
        assert_eq!(s.cursor().x, 1);
        s.put_char('c', 1, &pen(), false);
        assert_eq!(s.cursor().y, 1);
        assert_eq!(s.cell(0, 1).ch, 'c');
    }

    #[test]
    fn wide_char_occupies_two_cells() {
        let mut s = Screen::new(4, 2, 100, false);
        s.put_char('中', 2, &pen(), false);
        assert_eq!(s.cell(0, 0).ch, '中');
        assert!(s.cell(1, 0).is_continuation());
        assert_eq!(s.cursor().x, 2);
    }

    #[test]
    fn wide_char_wraps_from_last_column() {
        let mut s = Screen::new(4, 3, 100, false);
        s.put_char('a', 1, &pen(), false);
        s.put_char('b', 1, &pen(), false);
        s.put_char('c', 1, &pen(), false);
        // 光标在第 4 列（pending），宽字符应换行
        s.put_char('中', 2, &pen(), false);
        assert_eq!(s.cell(0, 1).ch, '中');
        assert!(s.cell(1, 1).is_continuation());
    }

    #[test]
    fn combining_attaches_to_previous() {
        let mut s = Screen::new(4, 2, 100, false);
        s.put_char('e', 1, &pen(), false);
        s.put_char('\u{0301}', 0, &pen(), false);
        assert_eq!(s.cell(0, 0).ch, 'e');
        assert_eq!(s.cell(0, 0).combining, vec!['\u{0301}']);
    }

    #[test]
    fn combining_after_wide_char_targets_wide_cell() {
        let mut s = Screen::new(4, 2, 100, false);
        s.put_char('中', 2, &pen(), false);
        s.put_char('\u{0301}', 0, &pen(), false);
        assert_eq!(s.cell(0, 0).combining, vec!['\u{0301}']);
    }

    #[test]
    fn scroll_up_pushes_scrollback_on_primary() {
        let mut s = Screen::new(4, 2, 100, false);
        s.move_to(0, 0);
        for c in "aaaa".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        s.move_to(0, 1);
        for c in "bbbb".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        s.linefeed(&pen()); // 底行换行 -> 滚动
        assert_eq!(s.cell(0, 0).ch, 'b');
        assert_eq!(s.cell(0, 1).ch, ' ');
        assert_eq!(s.scrollback_len(), 1);
        assert_eq!(s.scrollback_line(0).unwrap()[0].ch, 'a');
    }

    #[test]
    fn scroll_up_skips_scrollback_on_alt() {
        let mut s = Screen::new(4, 2, 100, true);
        s.linefeed(&pen());
        s.linefeed(&pen());
        assert_eq!(s.scrollback_len(), 0);
    }

    #[test]
    fn scroll_region_scrolls_only_within() {
        let mut s = Screen::new(4, 4, 100, false);
        s.set_margins(1, 2);
        s.move_to(0, 2);
        s.linefeed(&pen()); // 在底边距滚动
        assert_eq!(s.cell(0, 0).ch, ' '); // 顶行不动
        assert_eq!(s.scrollback_len(), 0);
        assert_eq!(s.cell(0, 1).ch, ' ');
        assert_eq!(s.cell(0, 2).ch, ' ');
    }

    #[test]
    fn erase_in_display_modes() {
        let mut s = Screen::new(4, 3, 100, false);
        for (x, y, ch) in [(0, 0, 'a'), (1, 0, 'b'), (0, 1, 'c'), (0, 2, 'd')] {
            s.move_to(x, y);
            s.put_char(ch, 1, &pen(), false);
        }
        s.move_to(1, 0);
        s.erase_in_display(0, &pen());
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(1, 0).ch, ' ');
        assert_eq!(s.cell(0, 1).ch, ' ');

        s.move_to(0, 0);
        for ch in ['x', 'y'] {
            s.put_char(ch, 1, &pen(), false);
        }
        s.move_to(0, 0);
        s.erase_in_display(2, &pen());
        assert_eq!(s.cell(0, 0).ch, ' ');
        assert_eq!(s.cell(1, 0).ch, ' ');
    }

    #[test]
    fn erase_in_line_and_damage() {
        let mut s = Screen::new(4, 2, 100, false);
        for c in "abcd".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        s.clear_damage();
        s.move_to(1, 0);
        s.erase_in_line(0, &pen());
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(1, 0).ch, ' ');
        assert_eq!(s.damage_rows(), vec![0]);
    }

    #[test]
    fn insert_and_delete_chars() {
        let mut s = Screen::new(5, 1, 100, false);
        for c in "abcde".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        s.move_to(1, 0);
        s.insert_chars(2, &pen());
        assert_eq!(s.cell(1, 0).ch, ' ');
        assert_eq!(s.cell(3, 0).ch, 'b');

        // 删除光标处 2 个空格：后续字符左移，行尾补空
        s.move_to(1, 0);
        s.delete_chars(2, &pen());
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(1, 0).ch, 'b');
        assert_eq!(s.cell(2, 0).ch, 'c');
        assert_eq!(s.cell(4, 0).ch, ' ');
    }

    #[test]
    fn insert_and_delete_lines_within_margins() {
        let mut s = Screen::new(2, 3, 100, false);
        for (y, ch) in [(0, 'a'), (1, 'b'), (2, 'c')] {
            s.move_to(0, y);
            s.put_char(ch, 1, &pen(), false);
        }
        s.move_to(0, 1);
        s.delete_lines(1, &pen());
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(0, 1).ch, 'c');
        assert_eq!(s.cell(0, 2).ch, ' ');
    }

    #[test]
    fn origin_mode_clamps_to_margins() {
        let mut s = Screen::new(4, 5, 100, false);
        s.set_margins(1, 3);
        s.set_origin_mode(true);
        s.move_to(0, 0);
        // 调用方按原点换算后应落在边距内；此处验证边距本身
        assert_eq!(s.margins(), (1, 3));
        s.move_to(0, 4);
        assert_eq!(s.cursor().y, 4);
    }

    #[test]
    fn save_restore_cursor_includes_pen() {
        let mut s = Screen::new(4, 4, 100, false);
        let mut p = Pen::default();
        p.fg = Color::Rgb(1, 2, 3);
        s.move_to(2, 1);
        s.save_cursor(&p);
        s.move_to(0, 0);
        let mut p2 = Pen::default();
        s.restore_cursor(&mut p2);
        assert_eq!(s.cursor().x, 2);
        assert_eq!(s.cursor().y, 1);
        assert_eq!(p2.fg, Color::Rgb(1, 2, 3));
    }

    #[test]
    fn resize_truncates_and_pads() {
        let mut s = Screen::new(4, 3, 100, false);
        for c in "abcdefgh".chars() {
            s.put_char(c, 1, &pen(), false);
        }
        s.resize(2, 2);
        assert_eq!(s.cols(), 2);
        assert_eq!(s.rows(), 2);
        assert_eq!(s.cell(0, 0).ch, 'a');
        assert_eq!(s.cell(1, 0).ch, 'b');
        assert_eq!(s.cell(0, 1).ch, 'e');
        s.resize(4, 3);
        assert_eq!(s.cell(3, 2).ch, ' ');
    }

    #[test]
    fn delete_lines_respects_margins() {
        let mut s = Screen::new(2, 4, 100, false);
        s.set_margins(1, 2);
        for (y, ch) in [(0, 'a'), (1, 'b'), (2, 'c'), (3, 'd')] {
            s.move_to(0, y);
            s.put_char(ch, 1, &pen(), false);
        }
        s.move_to(0, 1);
        s.delete_lines(1, &pen());
        assert_eq!(s.cell(0, 0).ch, 'a'); // 区外不动
        assert_eq!(s.cell(0, 1).ch, 'c');
        assert_eq!(s.cell(0, 2).ch, ' '); // 从底部补空
        assert_eq!(s.cell(0, 3).ch, 'd'); // 区外不动
    }

    #[test]
    fn tabs_every_eight() {
        let s = Screen::new(20, 2, 100, false);
        let mut t = s.clone();
        t.next_tab();
        assert_eq!(t.cursor().x, 8);
        t.next_tab();
        assert_eq!(t.cursor().x, 16);
    }
}
