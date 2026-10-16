//! 解析状态机：字符流 -> 语义事件（print/execute/CSI/ESC/OSC/DCS）。
//!
//! 参数支持 `;`（参数分隔）与 `:`（子参数分隔，用于 SGR 扩展颜色两种写法：
//! `38;2;r;g;b` 与 `38:2::r:g:b`）。非法/超长序列被丢弃或截断，保证不 panic。

/// 事件处理器（由 `TermCore` 实现）。
pub(crate) trait Handler {
    /// 可打印字符。
    fn print(&mut self, c: char);
    /// C0/C1 控制字节（0x00..=0x1F、0x7F）。
    fn execute(&mut self, byte: u8);
    /// CSI 序列。`params` 为按 `;` 分组、组内含 `:` 子参数。
    fn csi_dispatch(
        &mut self,
        params: &[Vec<u32>],
        private: Option<char>,
        intermediates: &[u8],
        final_byte: u8,
    );
    /// ESC 序列。
    fn esc_dispatch(&mut self, intermediates: &[u8], final_byte: u8);
    /// OSC 字符串（BEL 或 ST 终止）。
    fn osc_dispatch(&mut self, payload: &str);
    /// DCS 字符串（ST 终止）。
    fn dcs_dispatch(&mut self, payload: &str);
}

const MAX_GROUPS: usize = 64;
const MAX_SUBPARAMS: usize = 16;
const MAX_STRING: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Esc,
    Csi,
    Osc,
    OscEsc,
    Dcs,
    DcsEsc,
    /// SOS/PM/APC 字符串（只消费不派发）
    Str,
    StrEsc,
}

pub(crate) struct Parser {
    state: State,
    groups: Vec<Vec<u32>>,
    cur_group: Vec<u32>,
    cur_value: u32,
    private: Option<char>,
    intermediates: Vec<u8>,
    string: String,
    esc_intermediates: Vec<u8>,
}

impl Parser {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Ground,
            groups: Vec::new(),
            cur_group: Vec::new(),
            cur_value: 0,
            private: None,
            intermediates: Vec::new(),
            string: String::new(),
            esc_intermediates: Vec::new(),
        }
    }

    pub(crate) fn feed<H: Handler>(&mut self, c: char, h: &mut H) {
        match self.state {
            State::Ground => self.ground(c, h),
            State::Esc => self.esc(c, h),
            State::Csi => self.csi(c, h),
            State::Osc | State::Dcs | State::Str => self.string_body(c, h),
            State::OscEsc | State::DcsEsc | State::StrEsc => self.string_esc(c, h),
        }
    }

    fn ground<H: Handler>(&mut self, c: char, h: &mut H) {
        match c {
            '\u{1b}' => {
                self.esc_intermediates.clear();
                self.state = State::Esc;
            }
            '\u{00}'..='\u{1f}' | '\u{7f}' => h.execute(c as u8),
            _ => h.print(c),
        }
    }

    fn esc<H: Handler>(&mut self, c: char, h: &mut H) {
        match c {
            '[' => self.begin_csi(),
            ']' => self.begin_string(State::Osc),
            'P' => self.begin_string(State::Dcs),
            'X' | '^' | '_' => self.begin_string(State::Str),
            '\u{00}'..='\u{1f}' => h.execute(c as u8),
            '\u{7f}' => {}
            c if ('\u{20}'..='\u{2f}').contains(&c) => {
                if self.esc_intermediates.len() < 8 {
                    self.esc_intermediates.push(c as u8);
                }
            }
            c if ('\u{30}'..='\u{7e}').contains(&c) => {
                let fin = c as u8;
                let inter = std::mem::take(&mut self.esc_intermediates);
                self.state = State::Ground;
                h.esc_dispatch(&inter, fin);
            }
            _ => self.state = State::Ground, // 非 ASCII：中止
        }
    }

    fn begin_csi(&mut self) {
        self.groups.clear();
        self.cur_group.clear();
        self.cur_value = 0;
        self.private = None;
        self.intermediates.clear();
        self.state = State::Csi;
    }

    fn begin_string(&mut self, target: State) {
        self.string.clear();
        self.state = target;
    }

    fn csi<H: Handler>(&mut self, c: char, h: &mut H) {
        match c {
            '0'..='9' => {
                self.cur_value = (self.cur_value * 10 + (c as u32 - '0' as u32)).min(65_535);
            }
            ';' => self.csi_semicolon(),
            ':' => self.csi_colon(),
            '?' | '=' | '>' | '<' if self.private.is_none() && self.intermediates.is_empty() => {
                self.private = Some(c);
            }
            '\u{20}'..='\u{2f}' => {
                if self.intermediates.len() < 8 {
                    self.intermediates.push(c as u8);
                }
            }
            '\u{40}'..='\u{7e}' => {
                self.cur_group.push(self.cur_value);
                let groups = std::mem::take(&mut self.groups);
                // groups 只含已完成的分组；把当前组并入
                let mut all = groups;
                all.push(std::mem::take(&mut self.cur_group));
                let inter = std::mem::take(&mut self.intermediates);
                let private = self.private.take();
                self.state = State::Ground;
                h.csi_dispatch(&all, private, &inter, c as u8);
            }
            '\u{18}' | '\u{1a}' => self.state = State::Ground, // CAN/SUB 中止
            '\u{1b}' => {
                self.esc_intermediates.clear();
                self.state = State::Esc;
            }
            '\u{00}'..='\u{17}' | '\u{19}' | '\u{1c}'..='\u{1f}' => h.execute(c as u8),
            '\u{7f}' => {}
            _ => {} // 非 ASCII/非法字符：忽略
        }
    }

    fn csi_semicolon(&mut self) {
        if self.groups.len() < MAX_GROUPS {
            self.cur_group.push(self.cur_value);
            self.groups.push(std::mem::take(&mut self.cur_group));
        } else {
            // 分组超限：丢弃，但保持状态一致
            self.cur_group.clear();
        }
        self.cur_group = Vec::new();
        self.cur_value = 0;
    }

    fn csi_colon(&mut self) {
        if self.cur_group.len() < MAX_SUBPARAMS {
            self.cur_group.push(self.cur_value);
        }
        self.cur_value = 0;
    }

    fn string_body<H: Handler>(&mut self, c: char, h: &mut H) {
        match c {
            '\u{07}' => {
                let s = std::mem::take(&mut self.string);
                let st = self.state;
                self.state = State::Ground;
                self.finish_string(st, &s, h);
            }
            '\u{1b}' => {
                self.state = match self.state {
                    State::Osc => State::OscEsc,
                    State::Dcs => State::DcsEsc,
                    _ => State::StrEsc,
                };
            }
            '\u{18}' | '\u{1a}' => {
                self.string.clear();
                self.state = State::Ground;
            }
            _ => {
                if self.string.len() < MAX_STRING {
                    self.string.push(c);
                }
            }
        }
    }

    fn string_esc<H: Handler>(&mut self, c: char, h: &mut H) {
        if c == '\\' {
            let s = std::mem::take(&mut self.string);
            let st = self.state;
            self.state = State::Ground;
            self.finish_string(st, &s, h);
        } else {
            // 非 ST：容错 —— 把 ESC 内容并回字符串继续
            if self.string.len() + 2 <= MAX_STRING {
                self.string.push('\u{1b}');
                self.string.push(c);
            }
            self.state = match st_from_esc(self.state) {
                Some(s) => s,
                None => State::Ground,
            };
        }
    }

    fn finish_string<H: Handler>(&mut self, from: State, s: &str, h: &mut H) {
        match from {
            State::Osc | State::OscEsc => h.osc_dispatch(s),
            State::Dcs | State::DcsEsc => h.dcs_dispatch(s),
            _ => {} // SOS/PM/APC 忽略
        }
    }
}

fn st_from_esc(esc_state: State) -> Option<State> {
    match esc_state {
        State::OscEsc => Some(State::Osc),
        State::DcsEsc => Some(State::Dcs),
        State::StrEsc => Some(State::Str),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec {
        prints: String,
        execs: Vec<u8>,
        csis: Vec<(Vec<Vec<u32>>, Option<char>, Vec<u8>, u8)>,
        escs: Vec<(Vec<u8>, u8)>,
        oscs: Vec<String>,
        dcss: Vec<String>,
    }

    impl Handler for Rec {
        fn print(&mut self, c: char) {
            self.prints.push(c);
        }
        fn execute(&mut self, byte: u8) {
            self.execs.push(byte);
        }
        fn csi_dispatch(
            &mut self,
            params: &[Vec<u32>],
            private: Option<char>,
            intermediates: &[u8],
            final_byte: u8,
        ) {
            self.csis
                .push((params.to_vec(), private, intermediates.to_vec(), final_byte));
        }
        fn esc_dispatch(&mut self, intermediates: &[u8], final_byte: u8) {
            self.escs.push((intermediates.to_vec(), final_byte));
        }
        fn osc_dispatch(&mut self, payload: &str) {
            self.oscs.push(payload.to_string());
        }
        fn dcs_dispatch(&mut self, payload: &str) {
            self.dcss.push(payload.to_string());
        }
    }

    fn run(s: &str) -> Rec {
        let mut p = Parser::new();
        let mut r = Rec::default();
        for c in s.chars() {
            p.feed(c, &mut r);
        }
        r
    }

    #[test]
    fn plain_text_and_controls() {
        let r = run("ab\ncd\x07");
        assert_eq!(r.prints, "abcd");
        assert_eq!(r.execs, vec![0x0a, 0x07]);
    }

    #[test]
    fn csi_params_semicolon() {
        let r = run("\u{1b}[1;23H");
        assert_eq!(
            r.csis,
            vec![(vec![vec![1], vec![23]], None, vec![], b'H')]
        );
    }

    #[test]
    fn csi_empty_params_and_private() {
        let r = run("\u{1b}[;?7h");
        // ';' 产生空参数 0，随后 '7' 为私有参数位上的值
        assert_eq!(r.csis, vec![(vec![vec![0], vec![7]], Some('?'), vec![], b'h')]);
    }

    #[test]
    fn csi_colon_subparams() {
        let r = run("\u{1b}[38:2::255:128:0m");
        assert_eq!(
            r.csis,
            vec![(
                vec![vec![38, 2, 0, 255, 128, 0]],
                None,
                vec![],
                b'm'
            )]
        );
    }

    #[test]
    fn csi_intermediate_soft_reset() {
        let r = run("\u{1b}[!p");
        assert_eq!(r.csis, vec![(vec![vec![0]], None, vec![b'!'], b'p')]);
    }

    #[test]
    fn csi_abort_by_can() {
        let r = run("\u{1b}[123\u{18}x");
        assert!(r.csis.is_empty());
        assert_eq!(r.prints, "x");
    }

    #[test]
    fn osc_bel_and_st() {
        let r = run("\u{1b}]0;title\u{07}\u{1b}]2;two\u{1b}\\");
        assert_eq!(r.oscs, vec!["0;title", "2;two"]);
    }

    #[test]
    fn dcs_to_st() {
        let r = run("\u{1b}P1$r\u{1b}\\ok");
        assert_eq!(r.dcss, vec!["1$r"]);
        assert_eq!(r.prints, "ok");
    }

    #[test]
    fn esc_sequences() {
        let r = run("\u{1b}7\u{1b}M\u{1b}#8\u{1b}D");
        assert_eq!(
            r.escs,
            vec![
                (vec![], b'7'),
                (vec![], b'M'),
                (vec![b'#'], b'8'),
                (vec![], b'D'),
            ]
        );
    }

    #[test]
    fn unterminated_string_capped() {
        let mut p = Parser::new();
        let mut r = Rec::default();
        p.feed('\u{1b}', &mut r);
        p.feed(']', &mut r);
        for _ in 0..(MAX_STRING + 100) {
            p.feed('a', &mut r);
        }
        p.feed('\u{07}', &mut r);
        assert_eq!(r.oscs.len(), 1);
        assert!(r.oscs[0].len() <= MAX_STRING);
    }
}
