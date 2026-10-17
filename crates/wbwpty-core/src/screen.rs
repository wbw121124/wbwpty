//! The host's virtual screen.
//!
//! # Why it is here and not in the payload
//!
//! Because it cannot be in the payload. A virtual screen is a grid of cells: it
//! needs a heap, and `wbwpty-redirect` is `no_std` with no allocator (AGENTS rule
//! 3) - a worker thread in there may run before the target's CRT has a heap at
//! all. So the screen lives in the host, which has one, and the payload can only
//! ask about it.
//!
//! # What the payload gets, and how
//!
//! Not a round trip per call. Programs call `GetConsoleScreenBufferInfo` often
//! enough that a synchronous question would show up, so the state is **pushed**
//! into the payload's mapped image whenever it changes - the same mechanism the
//! project already uses for `WBWPTY_STATUS` and `WBWPTY_HOOK_STATS`: a word the
//! host writes with `WriteProcessMemory`, at an RVA it resolves from the export
//! table.
//!
//! The record is written under a **seqlock**, because a 32-byte struct written by
//! one process and read by another is otherwise a torn read waiting to happen, and
//! a torn cursor position is a program that jumps somewhere random. The counter
//! is odd while a write is in progress; a reader that sees it change underneath
//! reads again.
//!
//! # How stale is it, really
//!
//! As stale as the pipe read that produced it: the host feeds each chunk of
//! output into the screen before mirroring it onward, so by the time a terminal
//! has *displayed* the write that moved the cursor, the state has been published.
//! A program that queries in the same breath as it writes can still read the
//! position from before the write, because the host may not have read the write
//! off the pipe yet. That window is the pipe's latency, and it is the honest cost
//! of not answering synchronously. It is bounded, it does not grow, and closing
//! it would mean a synchronous round trip on every call.

use std::sync::Mutex;

use vt_parser::{Attrs, Color, Terminal, TerminalOptions};

/// What a console API is allowed to ask about.
///
/// Mirrors `wbwpty_redirect::console::ConsoleState` field for field. Neither
/// crate can depend on the other, so the layout is written twice and
/// [`ConsoleState::LAYOUT`] exists to be compared against the other side's.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConsoleState {
    /// Odd while the host is writing this record, even when it is complete.
    pub generation: u32,
    /// `1` once the host has ever published anything at all.
    ///
    /// Separate from `generation` because a zero record and a never-written one
    /// both read as all zeroes, and "the host has no idea where the cursor is"
    /// and "the cursor is at 0,0" are different answers for a program.
    pub valid: u32,
    /// Cursor position, zero-based.
    pub cursor_x: u32,
    pub cursor_y: u32,
    /// Window size in cells.
    pub cols: u32,
    pub rows: u32,
    /// `WORD` attribute of the cell under the cursor.
    pub attributes: u32,
    /// Non-zero when the cursor is visible.
    pub cursor_visible: u32,
    /// 1 when the alternate screen is active.
    pub alt_screen: u32,
    /// Non-zero when the target has turned on line wrap.
    pub wrap: u32,
}

impl ConsoleState {
    /// Size and alignment of the record, which is the whole of the contract with
    /// the payload's copy.
    pub const LAYOUT: (usize, usize) = (
        std::mem::size_of::<ConsoleState>(),
        std::mem::align_of::<ConsoleState>(),
    );

    fn encode(&self) -> [u8; std::mem::size_of::<ConsoleState>()] {
        // SAFETY: `ConsoleState` is `#[repr(C)]` and every field is a plain
        // integer, so all-zero bits is a valid value for each of them and the
        // byte order is the target's, which is the same machine.
        let mut raw = [0u8; std::mem::size_of::<ConsoleState>()];
        let fields = [
            self.generation,
            self.valid,
            self.cursor_x,
            self.cursor_y,
            self.cols,
            self.rows,
            self.attributes,
            self.cursor_visible,
            self.alt_screen,
            self.wrap,
        ];
        for (slot, value) in raw.chunks_mut(4).zip(fields) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        raw
    }
}

/// A virtual screen for one session.
///
/// Wraps the vendored `vt-parser`, and owns the two things a terminal API cannot
/// do for itself: turning bytes into state, and knowing what changed.
pub struct Screen {
    terminal: Terminal,
    /// Bumped on every publish so the payload can tell a torn read from a stale
    /// one, and so a caller can tell the screen moved at all.
    generation: u32,
}

impl Screen {
    /// A screen of the given geometry, with no scrollback.
    ///
    /// No scrollback on purpose: nothing in this project reads it back, and
    /// holding ten thousand lines a program can never scroll to is memory for
    /// nothing.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            terminal: Terminal::with_options(
                cols,
                rows,
                TerminalOptions {
                    scrollback_limit: 0,
                },
            ),
            generation: 0,
        }
    }

    /// Feeds bytes from the target.
    ///
    /// Takes a chunk that may split a UTF-8 sequence or an escape sequence at any
    /// point; `vt-parser`'s decoder keeps both across calls, which is the reason
    /// it is worth using rather than a `String::from_utf8_lossy` per chunk.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.terminal.feed(bytes);
    }

    /// Resizes, as a window change would.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.terminal.resize(cols, rows);
    }

    /// The current state, as the payload would read it.
    pub fn snapshot(&self) -> ConsoleState {
        let view = self.terminal.get_screen();
        ConsoleState {
            // Even, because `encode` is not called from here and this value only
            // leaves through a completed publish.
            generation: self.generation,
            valid: 1,
            cursor_x: view.cursor.x as u32,
            cursor_y: view.cursor.y as u32,
            cols: view.cols as u32,
            rows: view.rows as u32,
            attributes: attributes_of(&view),
            cursor_visible: u32::from(view.cursor.visible),
            alt_screen: u32::from(self.terminal.is_alt_screen()),
            wrap: 1,
        }
    }

    /// The record as the host writes it, generation included.
    ///
    /// Two writes, odd then even, and the payload's reader is written against
    /// exactly that. Doing it here rather than in the caller keeps the protocol in
    /// one place.
    ///
    /// The counter moves by one per half, not by two up front: a reader that
    /// looks at the low bit is asking "is a write in progress", and an even
    /// counter is the only answer that means "this record is whole".
    pub fn publish(
        &mut self,
    ) -> (
        [u8; std::mem::size_of::<ConsoleState>()],
        [u8; std::mem::size_of::<ConsoleState>()],
    ) {
        self.generation = self.generation.wrapping_add(1);
        let mut half = self.snapshot();
        half.generation = self.generation;
        let busy = half.encode();

        self.generation = self.generation.wrapping_add(1);
        half.generation = self.generation;
        (busy, half.encode())
    }

    /// The replies a terminal owes its program - DA, DSR, CPR - taken out.
    ///
    /// They belong on the target's **stdin**: a program that queries the terminal
    /// is waiting for the answer to arrive where it asked the question, and
    /// writing them to stdout would put the terminal's own answer into the user's
    /// terminal.
    pub fn take_replies(&mut self) -> Vec<u8> {
        self.terminal.take_replies()
    }

    /// The window title the program set, if any.
    pub fn title(&self) -> &str {
        self.terminal.title()
    }

    /// The cursor position, for tests and for `--verbose`.
    pub fn cursor(&self) -> (u16, u16) {
        let view = self.terminal.get_screen();
        (view.cursor.x, view.cursor.y)
    }
}

/// The console `WORD` attribute under the cursor.
///
/// The mapping from a cell's colour and attributes to a legacy `WORD` is the one
/// place where a virtual screen has to lie slightly to look real, because the
/// legacy attribute word is a palette index and `vt-parser` keeps real colours.
/// Palette 7 on white is what a legacy console would have shown, so that is what
/// is reported - a program comparing against `FOREGROUND_BLUE` gets a number, and
/// a program that sets an attribute and reads it back gets its own number, which
/// is the property programs actually depend on.
fn attributes_of(view: &vt_parser::ScreenView) -> u32 {
    const COMMON: u32 = 0x0007;
    const INTENSITY: u32 = 0x0008;
    const COMMON_BACKGROUND: u32 = 0x0070;
    const INTENSITY_BACKGROUND: u32 = 0x0080;

    let cell = view.cell(view.cursor.x, view.cursor.y);
    let (fg, bg) = match cell {
        Some(cell) => (cell.fg, cell.bg),
        None => (Color::Default, Color::Default),
    };
    let mut out = 0u32;
    if let Color::Indexed(index) = fg {
        if index < 8 {
            out |= index as u32 & COMMON;
        } else if index < 16 {
            out |= (index as u32 & COMMON) | INTENSITY;
        }
    }
    if let Color::Indexed(index) = bg {
        if index < 8 {
            out |= (index as u32 & COMMON) << 4;
        } else if index < 16 {
            out |= ((index as u32 & COMMON) << 4) | INTENSITY_BACKGROUND;
        }
    }
    let _ = COMMON_BACKGROUND;
    out
}

/// Whether a cell carries bold, which the legacy attribute word also encodes.
///
/// Kept beside [`attributes_of`] because it answers the same question and the
/// two must not drift apart.
pub fn cell_is_bold(cell: &vt_parser::Cell) -> bool {
    cell.attrs.contains(Attrs::BOLD)
}

/// The screen, shared between the output pump and whoever asks about it.
pub type SharedScreen = std::sync::Arc<Mutex<Screen>>;

/// Poison-tolerant access, for the same reason the pipe locks are.
pub fn lock(screen: &SharedScreen) -> std::sync::MutexGuard<'_, Screen> {
    screen
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_is_ten_words() {
        // The payload's copy is written by hand; if this changes, that changes.
        assert_eq!(ConsoleState::LAYOUT, (40, 4));
    }

    #[test]
    fn the_cursor_follows_what_was_written() {
        let mut screen = Screen::new(80, 25);
        screen.feed(b"abc");
        assert_eq!(screen.cursor(), (3, 0));
        screen.feed(b"\r\n");
        assert_eq!(screen.cursor(), (0, 1));
    }

    /// A chunk boundary in the middle of an escape sequence must not lose it.
    /// This is the whole reason the screen is fed a `vt-parser` rather than being
    /// decoded per read.
    #[test]
    fn a_sequence_split_across_chunks_still_lands() {
        let mut screen = Screen::new(80, 25);
        screen.feed(b"\x1b[3");
        screen.feed(b"1mred");
        let view = screen.terminal.get_screen();
        let cell = view.cell(0, 0).expect("a cell");
        assert_eq!(
            cell.fg,
            Color::Indexed(1),
            "SGR 31 did not survive the split"
        );
    }

    /// The seqlock has to hand out an odd word and an even one, or the payload's
    /// reader is checking nothing.
    #[test]
    fn the_seqlock_marks_its_two_halves() {
        let mut screen = Screen::new(80, 25);
        let (busy, done) = screen.publish();
        let word = |raw: &[u8]| u32::from_le_bytes(raw[..4].try_into().expect("4 bytes"));
        assert_eq!(
            word(&busy) & 1,
            1,
            "the first write must be marked in progress"
        );
        assert_eq!(
            word(&done) & 1,
            0,
            "the second write must be marked complete"
        );
    }
}
