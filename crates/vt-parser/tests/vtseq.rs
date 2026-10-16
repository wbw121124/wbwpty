//! 公开 API 端到端测试（字节流 -> 屏幕断言），覆盖规格点名的 VT 特性。

use vt_parser::{Attrs, Color, MouseEncoding, MouseMode, Terminal, TerminalOptions};

fn feed(t: &mut Terminal, s: &str) {
    t.feed(s.as_bytes());
}

#[test]
fn damage_lifecycle() {
    let mut t = Terminal::new(20, 5);
    feed(&mut t, "\u{1b}[2J\u{1b}[H");
    assert!(!t.get_screen().damage.is_empty()); // 清屏全行 damage
    t.clear_damage();
    assert!(t.get_screen().damage.is_empty());
    feed(&mut t, "\u{1b}[2;2Hx");
    assert_eq!(t.get_screen().damage, vec![1]);
}

#[test]
fn feed_split_inside_csi() {
    let mut t = Terminal::new(20, 5);
    t.feed(b"\x1b[");
    t.feed(b"3;4");
    t.feed(b"Hok");
    let v = t.get_screen();
    assert_eq!(v.cell(3, 2).unwrap().ch, 'o');
    assert_eq!(v.cell(4, 2).unwrap().ch, 'k');
    assert_eq!(v.cursor.y, 2);
}

#[test]
fn alt_screen_1049_roundtrip_preserves_primary_and_cursor() {
    let mut t = Terminal::new(20, 5);
    feed(&mut t, "primary-line\u{1b}[5;7H");
    feed(&mut t, "\u{1b}[?1049h"); // 进备用屏（保存光标）
    assert!(t.is_alt_screen());
    assert_eq!(t.get_screen().cursor.x, 0);
    feed(&mut t, "alt");
    assert_eq!(t.get_screen().line_text(0), "alt");
    feed(&mut t, "\u{1b}[?1049l");
    assert!(!t.is_alt_screen());
    let v = t.get_screen();
    assert_eq!(v.line_text(0), "primary-line");
    assert_eq!((v.cursor.x, v.cursor.y), (6, 4)); // 恢复到 5;7H
}

#[test]
fn truecolor_and_attrs_surface_in_cells() {
    let mut t = Terminal::new(20, 3);
    feed(&mut t, "\u{1b}[48;2;12;34;56;38;5;201m\u{1b}[3mV\u{1b}[0mN");
    let v = t.get_screen();
    let c = v.cell(0, 0).unwrap();
    assert_eq!(c.fg, Color::Indexed(201));
    assert_eq!(c.bg, Color::Rgb(12, 34, 56));
    assert!(c.attrs.contains(Attrs::ITALIC));
    let n = v.cell(1, 0).unwrap();
    assert_eq!(n.fg, Color::Default);
    assert!(!n.attrs.contains(Attrs::ITALIC));
}

#[test]
fn wide_and_combining_via_public_api() {
    let mut t = Terminal::new(20, 3);
    feed(&mut t, "e\u{0301}\u{4e2d}");
    let v = t.get_screen();
    let e = v.cell(0, 0).unwrap();
    assert_eq!(e.ch, 'e');
    assert_eq!(e.combining, vec!['\u{0301}']);
    // 宽字符从中文前面的组合符后开始于第 1 列
    assert!(v.cell(2, 0).unwrap().is_continuation() || v.cell(1, 0).unwrap().ch == '\u{4e2d}');
}

#[test]
fn mouse_paste_focus_modes_track() {
    let mut t = Terminal::new(10, 3);
    assert_eq!(t.mouse_mode(), MouseMode::None);
    feed(&mut t, "\u{1b}[?1002h\u{1b}[?1006h\u{1b}[?1004h\u{1b}[?2004h");
    assert_eq!(t.mouse_mode(), MouseMode::Button);
    assert_eq!(t.mouse_encoding(), MouseEncoding::Sgr);
    assert!(t.focus_reporting());
    assert!(t.bracketed_paste());
    feed(&mut t, "\u{1b}[?1002l\u{1b}[?1006l\u{1b}[?1004l\u{1b}[?2004l");
    assert_eq!(t.mouse_mode(), MouseMode::None);
    assert_eq!(t.mouse_encoding(), MouseEncoding::Legacy);
    assert!(!t.focus_reporting());
    assert!(!t.bracketed_paste());
}

#[test]
fn application_cursor_keys_and_keypad_track() {
    let mut t = Terminal::new(10, 3);
    assert!(!t.application_cursor_keys());
    assert!(!t.application_keypad());
    feed(&mut t, "\u{1b}[?1h\u{1b}=");
    assert!(t.application_cursor_keys());
    assert!(t.application_keypad());
    feed(&mut t, "\u{1b}[?1l\u{1b}>");
    assert!(!t.application_cursor_keys());
    assert!(!t.application_keypad());
}

#[test]
fn scroll_region_with_reverse_index() {
    let mut t = Terminal::with_options(10, 4, TerminalOptions { scrollback_limit: 0 });
    feed(&mut t, "\u{1b}[2;3r"); // 边距 = 行2..3
    feed(&mut t, "\u{1b}[2;1HA\r\nB\r\nC");
    // 顶行与底行不受滚动影响（滚动区内最多两行）
    let v = t.get_screen();
    assert_eq!(v.line_text(0), "");
    feed(&mut t, "\u{1b}[2;1H\u{1b}M"); // RI 在区顶 -> 区内下滚
    assert_eq!(t.get_screen().line_text(3), "");
}

#[test]
fn dsr_reports_origin_relative_position() {
    let mut t = Terminal::new(10, 6);
    feed(&mut t, "\u{1b}[3;5r\u{1b}[?6h\u{1b}[2;2H\u{1b}[6n");
    // 原点模式：行2相对 -> 绝对行4（1-based 报告 = 2）
    assert_eq!(t.take_replies(), "\u{1b}[2;2R".as_bytes());
}

#[test]
fn resize_mid_stream_keeps_parser_state() {
    let mut t = Terminal::new(20, 5);
    feed(&mut t, "\u{1b}[1;10H");
    t.resize(12, 4);
    feed(&mut t, "Z");
    let v = t.get_screen();
    assert_eq!((v.cols, v.rows), (12, 4));
    assert_eq!(v.cell(9, 0).unwrap().ch, 'Z'); // x=9 仍在 12 列内
}

#[test]
fn garbage_input_does_not_panic() {
    let mut t = Terminal::new(10, 3);
    // 非法 UTF-8、截断序列、深嵌套字符串
    t.feed(&[0xff, 0xfe, 0xc0, 0x80]);
    t.feed(b"\x1b[2J\x1b[H"); // 清掉替换符
    t.feed(b"\x1b[999999999999;38;2mok");
    t.feed(b"\x1b]0;never-terminated");
    t.feed(b"\x1bPhidden\x1b\\end");
    t.feed(&[0x1b, 0x5b, 0x00, 0x9b]);
    assert_eq!(t.get_screen().line_text(0), "okend");
}

#[test]
fn title_icon_and_bell() {
    let mut t = Terminal::new(10, 3);
    feed(&mut t, "\u{1b}]1;icon-name\u{07}\u{1b}]2;window-title\u{1b}\\ding\u{07}");
    assert_eq!(t.title(), "window-title");
    assert_eq!(t.icon_title(), "icon-name");
    assert_eq!(t.bell_count(), 1);
}

#[test]
fn insert_mode_and_erase_roundtrip() {
    let mut t = Terminal::new(10, 3);
    feed(&mut t, "\u{1b}[2J\u{1b}[Habcd\u{1b}[1;2H\u{1b}[4hX");
    assert_eq!(t.get_screen().line_text(0), "aXbcd");
    feed(&mut t, "\u{1b}[4l\u{1b}[1;1H\u{1b}[2K");
    assert_eq!(t.get_screen().line_text(0), "");
}
