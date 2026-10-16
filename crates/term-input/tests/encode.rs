//! term-input 公共 API 集成测试：状态机、模式回灌、端到端编码流。

use term_input::{
    ArrowKey, Encoding, Encoder, InputEvent, KeyCode, KeyEvent, Modifiers, MouseButton,
    MouseEvent, MouseAction, NumpadKey,
};

fn bytes(e: &Encoder, ev: InputEvent) -> Vec<u8> {
    e.encode(&ev).expect("event must encode")
}

#[test]
fn default_state() {
    let e = Encoder::new();
    assert!(!e.cursor_keys_app());
    assert!(!e.keypad_app());
    assert_eq!(e.mouse_mode(), term_input::MouseMode::Off);
    assert_eq!(e.encoding(), Encoding::Legacy);
    assert!(!e.bracketed_paste());
    assert_eq!(Encoder::default().encode_paste("x"), b"x");
}

#[test]
fn mode_refeed_from_terminal() {
    // 模拟 vt-parser 检出 DECSET 后回灌：DECCKM(1)、keypad app、1000+1006、2004
    let mut e = Encoder::new();
    e.set_cursor_keys_app(true);
    e.set_keypad_app(true);
    e.set_mouse_mode(term_input::MouseMode::Normal);
    e.set_encoding(Encoding::Sgr);
    e.set_bracketed_paste(true);

    assert_eq!(
        bytes(&e, InputEvent::Key(KeyEvent::plain(KeyCode::Arrow(ArrowKey::Up)))),
        b"\x1bOA"
    );
    assert_eq!(
        bytes(&e, InputEvent::Key(KeyEvent::plain(KeyCode::Numpad(NumpadKey::Num('3'))))),
        b"\x1bOs"
    );
    assert_eq!(
        bytes(&e, InputEvent::Mouse(MouseEvent::new(
            MouseAction::Press(MouseButton::Left), 12, 34, Modifiers::NONE
        ))),
        b"\x1b[<0;12;34M"
    );
    assert_eq!(bytes(&e, InputEvent::Paste("p".into())), b"\x1b[200~p\x1b[201~");

    // 复位（RIS/DECRST）后回到默认
    let mut r = Encoder::new();
    r.set_cursor_keys_app(false);
    r.set_keypad_app(false);
    r.set_mouse_mode(term_input::MouseMode::Off);
    r.set_encoding(Encoding::Legacy);
    r.set_bracketed_paste(false);
    assert_eq!(
        bytes(&r, InputEvent::Key(KeyEvent::plain(KeyCode::Arrow(ArrowKey::Up)))),
        b"\x1b[A"
    );
    assert_eq!(
        r.encode(&InputEvent::Mouse(MouseEvent::new(
            MouseAction::Press(MouseButton::Left), 1, 1, Modifiers::NONE
        ))),
        None
    );
}

#[test]
fn all_plain_keys_produce_output() {
    let e = Encoder::new();
    let keys = [
        KeyCode::Char('z'),
        KeyCode::Enter,
        KeyCode::Tab,
        KeyCode::Backspace,
        KeyCode::Escape,
        KeyCode::Insert,
        KeyCode::Delete,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Arrow(ArrowKey::Up),
        KeyCode::Arrow(ArrowKey::Down),
        KeyCode::Arrow(ArrowKey::Left),
        KeyCode::Arrow(ArrowKey::Right),
        KeyCode::F(1),
        KeyCode::F(5),
        KeyCode::F(12),
        KeyCode::Numpad(NumpadKey::Num('9')),
        KeyCode::Numpad(NumpadKey::Divide),
    ];
    for k in keys {
        let out = e.encode(&InputEvent::Key(KeyEvent::plain(k)));
        assert!(out.is_some(), "no output for {k:?}");
        assert!(!out.unwrap().is_empty());
    }
    assert_eq!(e.encode(&InputEvent::Key(KeyEvent::plain(KeyCode::Unidentified))), None);
    assert_eq!(e.encode(&InputEvent::Key(KeyEvent::plain(KeyCode::F(13)))), None);
    assert_eq!(e.encode(&InputEvent::Key(KeyEvent::plain(KeyCode::F(24)))), None);
}

#[test]
fn modifier_matrix_on_arrow_up() {
    let e = Encoder::new();
    let cases: &[(Modifiers, &[u8])] = &[
        (Modifiers::NONE, b"\x1b[A"),
        (Modifiers::SHIFT, b"\x1b[1;2A"),
        (Modifiers::ALT, b"\x1b[1;3A"),
        (Modifiers::CTRL, b"\x1b[1;5A"),
        (Modifiers::META, b"\x1b[1;9A"),
        (Modifiers::SHIFT | Modifiers::ALT, b"\x1b[1;4A"),
        (Modifiers::ALT | Modifiers::CTRL, b"\x1b[1;7A"),
        (Modifiers::SHIFT | Modifiers::ALT | Modifiers::CTRL | Modifiers::META, b"\x1b[1;16A"),
    ];
    for (mods, expect) in cases {
        assert_eq!(
            e.encode(&InputEvent::Key(KeyEvent::new(KeyCode::Arrow(ArrowKey::Up), *mods))),
            Some(expect.to_vec()),
            "mods={mods:?}"
        );
    }
}

#[test]
fn mouse_modifier_matrix_sgr() {
    let mut e = Encoder::new();
    e.set_mouse_mode(term_input::MouseMode::Motion);
    e.set_encoding(Encoding::Sgr);
    let cases: &[(Modifiers, &[u8])] = &[
        (Modifiers::NONE, b"\x1b[<1;10;10M"),
        (Modifiers::SHIFT, b"\x1b[<5;10;10M"),
        (Modifiers::ALT, b"\x1b[<9;10;10M"),
        (Modifiers::CTRL, b"\x1b[<17;10;10M"),
        (Modifiers::SHIFT | Modifiers::CTRL, b"\x1b[<21;10;10M"),
    ];
    for (mods, expect) in cases {
        assert_eq!(
            e.encode(&InputEvent::Mouse(MouseEvent::new(
                MouseAction::Press(MouseButton::Middle), 10, 10, *mods
            ))),
            Some(expect.to_vec()),
            "mods={mods:?}"
        );
    }
    // 无键移动（1003 才报）
    assert_eq!(
        e.encode(&InputEvent::Mouse(MouseEvent::new(
            MouseAction::Move, 7, 8, Modifiers::NONE
        ))),
        Some(b"\x1b[<35;7;8M".to_vec()) // 3+32=35
    );
}

#[test]
fn event_stream_preserves_order() {
    let mut e = Encoder::new();
    e.set_bracketed_paste(true);
    let events = [
        InputEvent::Key(KeyEvent::plain(KeyCode::Char('h'))),
        InputEvent::Key(KeyEvent::plain(KeyCode::Char('i'))),
        InputEvent::Paste("!".into()),
        InputEvent::Key(KeyEvent::plain(KeyCode::Enter)),
    ];
    let mut stream = Vec::new();
    for ev in &events {
        stream.extend(e.encode(ev).expect("encode"));
    }
    assert_eq!(stream, b"hi\x1b[200~!\x1b[201~\r");
}
