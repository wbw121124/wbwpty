//! 增量 UTF-8 解码：容忍任意字节边界切分的输入（跨 feed 调用保持状态）。

pub(crate) struct Utf8Decoder {
    buf: [u8; 4],
    filled: usize,
    expected: usize,
}

fn lead_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        // 0x80..=0xC1 (孤立续字节/过长前缀) 与 0xF5..=0xFF 非法
        _ => 0,
    }
}

impl Utf8Decoder {
    pub(crate) fn new() -> Self {
        Self { buf: [0; 4], filled: 0, expected: 0 }
    }

    /// 逐字节喂入；完整序列或非法序列产生回调。非法序列 -> U+FFFD。
    pub(crate) fn feed<F: FnMut(char)>(&mut self, bytes: &[u8], mut emit: F) {
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if self.expected == 0 {
                match lead_len(b) {
                    0 => {
                        emit('\u{fffd}');
                        i += 1;
                    }
                    1 => {
                        emit(b as char);
                        i += 1;
                    }
                    n => {
                        self.buf[0] = b;
                        self.filled = 1;
                        self.expected = n;
                        i += 1;
                    }
                }
            } else if b & 0xc0 == 0x80 {
                self.buf[self.filled] = b;
                self.filled += 1;
                i += 1;
                if self.filled == self.expected {
                    self.flush(&mut emit);
                }
            } else {
                // 续字节缺失/中断：冲掉已缓冲部分，当前字节重新处理
                emit('\u{fffd}');
                self.filled = 0;
                self.expected = 0;
            }
        }
    }

    fn flush<F: FnMut(char)>(&mut self, emit: &mut F) {
        match std::str::from_utf8(&self.buf[..self.filled]) {
            Ok(s) => {
                for c in s.chars() {
                    emit(c);
                }
            }
            Err(_) => emit('\u{fffd}'),
        }
        self.filled = 0;
        self.expected = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(bytes: &[u8]) -> String {
        let mut d = Utf8Decoder::new();
        let mut s = String::new();
        d.feed(bytes, |c| s.push(c));
        s
    }

    #[test]
    fn ascii_passthrough() {
        assert_eq!(collect(b"hi\x07"), "hi\u{7}");
    }

    #[test]
    fn multibyte_complete() {
        assert_eq!(collect("\u{4e2d}\u{1f600}".as_bytes()), "\u{4e2d}\u{1f600}");
    }

    #[test]
    fn split_across_feeds() {
        let bytes = "é中".as_bytes();
        let mut d = Utf8Decoder::new();
        let mut s = String::new();
        for b in bytes {
            d.feed(&[*b], |c| s.push(c));
        }
        assert_eq!(s, "é中");
    }

    #[test]
    fn invalid_lead_and_truncation() {
        assert_eq!(collect(b"\xff"), "\u{fffd}");
        // 序列被非续字节打断
        assert_eq!(collect(b"\xc3A"), "\u{fffd}A");
        // 尾部不完整序列保留在缓冲区，无输出
        let mut d = Utf8Decoder::new();
        let mut s = String::new();
        d.feed(b"\xe4\xb8", |c| s.push(c));
        assert_eq!(s, "");
        d.feed(b"\xad", |c| s.push(c));
        assert_eq!(s, "\u{4e2d}");
    }

    #[test]
    fn overlong_and_surrogate_rejected() {
        assert_eq!(collect(b"\xc0\x80"), "\u{fffd}\u{fffd}");
        assert_eq!(collect(b"\xed\xa0\x80"), "\u{fffd}");
    }
}
