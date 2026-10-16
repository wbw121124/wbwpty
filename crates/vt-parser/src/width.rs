//! 字符显示宽度（列数）。近似 UAX#11 East Asian Width + 常见零宽/emoji 区段。
//!
//! 返回 0（组合符/零宽）、1（普通）或 2（East Asian Wide/Fullwidth 及 emoji）。
//! 精确的 Unicode 版本表属于大依赖，本实现取规格所需的近似子集并以测试锁定
//! 常用字符；阶段 5 可按需替换为数据表驱动。

/// 返回 `c` 占用的终端列数（0 / 1 / 2）。
pub fn char_width(c: char) -> usize {
    let cp = c as u32;

    // 控制字符不打印（解析层不会走到这里）
    if cp < 0x20 || (0x7f..0xa0).contains(&cp) {
        return 0;
    }

    if is_zero_width(cp) {
        return 0;
    }
    if is_wide(cp) {
        return 2;
    }
    1
}

fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|&(lo, hi)| cp >= lo && cp <= hi)
}

fn is_zero_width(cp: u32) -> bool {
    const ZERO: &[(u32, u32)] = &[
        // 组合变音符号（节选高频区段）
        (0x0300, 0x036f),
        (0x0483, 0x0489),
        (0x0591, 0x05bd),
        (0x05bf, 0x05bf),
        (0x05c1, 0x05c2),
        (0x05c4, 0x05c5),
        (0x05c7, 0x05c7),
        (0x0610, 0x061a),
        (0x064b, 0x065f),
        (0x0670, 0x0670),
        (0x06d6, 0x06dc),
        (0x06df, 0x06e4),
        (0x06e7, 0x06e8),
        (0x06ea, 0x06ed),
        (0x0711, 0x0711),
        (0x0730, 0x074a),
        (0x07a6, 0x07b0),
        (0x07eb, 0x07f3),
        (0x0816, 0x0819),
        (0x081b, 0x0823),
        (0x0825, 0x0827),
        (0x0829, 0x082d),
        (0x0859, 0x085b),
        (0x08e3, 0x0902),
        (0x093a, 0x093a),
        (0x093c, 0x093c),
        (0x0941, 0x0948),
        (0x094d, 0x094d),
        (0x0951, 0x0957),
        (0x0962, 0x0963),
        // 零宽格式字符
        (0x200b, 0x200f),
        (0x202a, 0x202e),
        (0x2060, 0x2064),
        (0x206a, 0x206f),
        // 音标扩展/组合符号
        (0x1ab0, 0x1aff),
        (0x1dc0, 0x1dff),
        (0x20d0, 0x20f0),
        // 变选择符
        (0xfe00, 0xfe0f),
        (0xfe20, 0xfe2f),
        // Hangul 连接元音/终声（在音节块内参与组合）
        (0x1160, 0x11ff),
        // 其他
        (0xe0100, 0xe01ef),
    ];
    in_ranges(cp, ZERO)
}

fn is_wide(cp: u32) -> bool {
    const WIDE: &[(u32, u32)] = &[
        // Hangul Jamo 初声
        (0x1100, 0x115f),
        // CJK 部首/符号/假名/注音/笔画
        (0x2e80, 0x303e),
        // 平假名/片假名/注音扩展/兼容
        (0x3041, 0x33ff),
        // CJK 统一表意（扩展 A 及主区）
        (0x3400, 0x4dbf),
        (0x4e00, 0x9fff),
        // Yi 音节/音节扩展
        (0xa000, 0xa4cf),
        // Hangul Jamo 扩展-A
        (0xa960, 0xa97f),
        // Hangul 音节
        (0xac00, 0xd7a3),
        // CJK 兼容表意
        (0xf900, 0xfaff),
        // 竖排标点/兼容形式
        (0xfe10, 0xfe19),
        (0xfe30, 0xfe6f),
        // 全角形式
        (0xff00, 0xff60),
        (0xffe0, 0xffe6),
        // Emoji/象形符号（常用区段）
        (0x1f004, 0x1f004),
        (0x1f0cf, 0x1f0cf),
        (0x1f18e, 0x1f19a),
        (0x1f200, 0x1f320),
        (0x1f32d, 0x1f335),
        (0x1f337, 0x1f37c),
        (0x1f37e, 0x1f393),
        (0x1f3a0, 0x1f3ca),
        (0x1f3cf, 0x1f3d3),
        (0x1f3e0, 0x1f3f0),
        (0x1f3f4, 0x1f3f4),
        (0x1f3f8, 0x1f43e),
        (0x1f440, 0x1f440),
        (0x1f442, 0x1f4fc),
        (0x1f4ff, 0x1f53d),
        (0x1f54b, 0x1f54e),
        (0x1f550, 0x1f567),
        (0x1f57a, 0x1f57a),
        (0x1f595, 0x1f596),
        (0x1f5a4, 0x1f5a4),
        (0x1f5fb, 0x1f64f),
        (0x1f680, 0x1f6c5),
        (0x1f6cc, 0x1f6cc),
        (0x1f6d0, 0x1f6d2),
        (0x1f6eb, 0x1f6ec),
        (0x1f6f4, 0x1f6fc),
        (0x1f7e0, 0x1f7eb),
        (0x1f90c, 0x1f93a),
        (0x1f93c, 0x1f945),
        (0x1f947, 0x1f9ff),
        (0x1fa70, 0x1faff),
        // 平面 2/3 CJK
        (0x20000, 0x2fffd),
        (0x30000, 0x3fffd),
    ];
    in_ranges(cp, WIDE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_one() {
        assert_eq!(char_width('A'), 1);
        assert_eq!(char_width('~'), 1);
        assert_eq!(char_width(' '), 1);
    }

    #[test]
    fn cjk_is_two() {
        assert_eq!(char_width('中'), 2);
        assert_eq!(char_width('문'), 2);
        assert_eq!(char_width('Ａ'), 2); // 全角
        assert_eq!(char_width('ﾊ'), 1); // 半角片假名
    }

    #[test]
    fn combining_is_zero() {
        assert_eq!(char_width('\u{0301}'), 0); // 组合尖音符
        assert_eq!(char_width('\u{200d}'), 0); // ZWJ
        assert_eq!(char_width('\u{fe0f}'), 0); // 变选择符
    }

    #[test]
    fn emoji_is_two() {
        assert_eq!(char_width('\u{1f600}'), 2);
        assert_eq!(char_width('\u{1f4a9}'), 2);
    }

    #[test]
    fn controls_are_zero() {
        assert_eq!(char_width('\n'), 0);
        assert_eq!(char_width('\u{7f}'), 0);
    }
}
