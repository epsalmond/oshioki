//! Rendering untrusted text on a terminal.
//!
//! Device labels, commands, working directories, and process names all reach
//! an operator's terminal from somewhere else: a requesting host, a paired
//! device, or `/proc`. Two classes of character can make that text lie about
//! itself, so both are escaped rather than printed:
//!
//! * control characters (C0 and C1: ESC, CR, DEL and friends), which move the
//!   cursor, clear the line, or repaint the screen; and
//! * invisible formatting characters — zero-width spaces, the bidirectional
//!   overrides and isolates, the byte order mark, and the rest of the Cf
//!   category — which reorder or hide text without leaving a mark.
//!
//! Escaped output stays unambiguous because the backslash that introduces an
//! escape is escaped too.

use std::fmt::Write as _;

/// Formatting characters that render as nothing, or reorder what follows.
///
/// This is the Cf (format) category plus the zero-width space, listed as
/// explicit ranges to avoid a Unicode table dependency. Everything else that
/// can rewrite a line is a control character and is caught by
/// [`char::is_control`].
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),   // soft hyphen
    (0x0600, 0x0605),   // Arabic number signs
    (0x061c, 0x061c),   // Arabic letter mark
    (0x06dd, 0x06dd),   // Arabic end of ayah
    (0x070f, 0x070f),   // Syriac abbreviation mark
    (0x0890, 0x0891),   // Arabic pound and piastre marks
    (0x08e2, 0x08e2),   // Arabic disputed end of ayah
    (0x180e, 0x180e),   // Mongolian vowel separator
    (0x200b, 0x200f),   // zero width space, joiners, LRM, RLM
    (0x202a, 0x202e),   // bidirectional embeddings and overrides
    (0x2060, 0x2064),   // word joiner and invisible operators
    (0x2066, 0x206f),   // bidirectional isolates and deprecated formatting
    (0xfeff, 0xfeff),   // byte order mark
    (0xfff9, 0xfffb),   // interlinear annotation marks
    (0x110bd, 0x110bd), // Kaithi number sign
    (0x110cd, 0x110cd), // Kaithi number sign above
    (0x13430, 0x1343f), // Egyptian hieroglyph format controls
    (0x1bca0, 0x1bca3), // Shorthand format controls
    (0x1d173, 0x1d17a), // musical notation format controls
    (0xe0001, 0xe0001), // language tag
    (0xe0020, 0xe007f), // tag characters
];

fn is_invisible(character: char) -> bool {
    let code = character as u32;
    INVISIBLE_RANGES
        .iter()
        .any(|&(low, high)| (low..=high).contains(&code))
}

/// Renders untrusted text for a terminal, escaping anything that could
/// repaint, reorder, or hide what the operator is reading.
#[must_use]
pub fn escape_for_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\\' {
            escaped.push_str("\\\\");
        } else if character.is_control() || is_invisible(character) {
            let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escape_for_terminal;

    #[test]
    fn escapes_terminal_control_sequences() {
        // A command that clears the line and prints a harmless one instead.
        assert_eq!(
            escape_for_terminal("/bin/rm -rf /\x1b[2K\rls"),
            "/bin/rm -rf /\\u{001b}[2K\\u{000d}ls"
        );
        // C1 controls have a one-byte escape in some terminals too.
        assert_eq!(
            escape_for_terminal("a\u{9b}b\u{7f}"),
            "a\\u{009b}b\\u{007f}"
        );
        // Backslashes are escaped so the rendering is unambiguous.
        assert_eq!(escape_for_terminal(r"C:\x1b"), r"C:\\x1b");
        // Ordinary text, including non-ASCII, passes through.
        assert_eq!(
            escape_for_terminal("お仕置き /usr/bin/id"),
            "お仕置き /usr/bin/id"
        );
    }

    /// Invisible formatting characters hide or reorder text without moving
    /// the cursor, so they are escaped like controls.
    #[test]
    fn escapes_invisible_and_bidirectional_characters() {
        // A right-to-left override reverses everything after it: what looks
        // like `/usr/bin/id` on screen is `di/nib/rsu/`.
        assert_eq!(
            escape_for_terminal("/bin/rm\u{202e}di/nib/rsu/"),
            "/bin/rm\\u{202e}di/nib/rsu/"
        );
        // Zero-width characters split a word into something that reads as
        // one command but is not.
        assert_eq!(
            escape_for_terminal("rm\u{200b}\u{200d}-rf"),
            "rm\\u{200b}\\u{200d}-rf"
        );
        // Isolates, the BOM, and tag characters are invisible too.
        assert_eq!(
            escape_for_terminal("a\u{2066}b\u{2069}c\u{feff}d\u{e0041}"),
            "a\\u{2066}b\\u{2069}c\\u{feff}d\\u{e0041}"
        );
        // The soft hyphen prints as nothing in most terminals.
        assert_eq!(escape_for_terminal("su\u{ad}do"), "su\\u{00ad}do");
        // Characters just outside the escaped ranges still pass through.
        assert_eq!(escape_for_terminal("\u{2065}\u{2010}"), "\u{2065}\u{2010}");
    }
}
