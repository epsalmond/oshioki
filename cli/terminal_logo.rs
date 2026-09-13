//! Optional Kitty graphics output for interactive top-level CLI help.

use std::ffi::OsStr;
use std::io::{self, IsTerminal as _, Write};

const IMAGE_CHUNK_SIZE: usize = 4096;
const IMAGE_WIDTH_CELLS: usize = 8;
const IMAGE_HEIGHT_CELLS: usize = 4;

/// Returns whether arguments request the top-level help page.
pub fn is_top_level_help(arguments: &[std::ffi::OsString]) -> bool {
    match arguments {
        [] => true,
        [flag] => {
            flag == OsStr::new("help") || flag == OsStr::new("-h") || flag == OsStr::new("--help")
        }
        _ => false,
    }
}

/// Prints the logo for a top-level help request when the terminal supports it.
pub fn maybe_print_for_arguments(arguments: &[std::ffi::OsString]) {
    if !is_top_level_help(arguments) || !io::stdout().is_terminal() {
        return;
    }
    if !supports_kitty_graphics(
        std::env::var("TERM_PROGRAM").ok().as_deref(),
        std::env::var("TERM").ok().as_deref(),
        std::env::var_os("TMUX").is_some(),
        std::env::var_os("STY").is_some(),
    ) {
        return;
    }
    let _ = write_logo(&mut io::stdout());
}

fn supports_kitty_graphics(
    term_program: Option<&str>,
    term: Option<&str>,
    tmux: bool,
    screen: bool,
) -> bool {
    if tmux || screen {
        return false;
    }
    let term = term.unwrap_or_default().to_ascii_lowercase();
    if term == "dumb" || term.starts_with("screen") || term.starts_with("tmux") {
        return false;
    }
    let term_program = term_program.unwrap_or_default().to_ascii_lowercase();
    matches!(term_program.as_str(), "kitty" | "wezterm" | "ghostty")
        || matches!(term.as_str(), "xterm-kitty" | "xterm-ghostty" | "wezterm")
}

fn write_logo(output: &mut impl Write) -> io::Result<()> {
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../assets/oshioki-cli.png"
        )),
    );
    let chunk_count = encoded.len().div_ceil(IMAGE_CHUNK_SIZE);
    for (index, chunk) in encoded.as_bytes().chunks(IMAGE_CHUNK_SIZE).enumerate() {
        let more = index + 1 < chunk_count;
        if index == 0 {
            write!(
                output,
                "\x1b_Ga=T,f=100,q=2,C=1,c={IMAGE_WIDTH_CELLS},r={IMAGE_HEIGHT_CELLS},m={};{}\x1b\\",
                usize::from(more),
                std::str::from_utf8(chunk).expect("base64 is ASCII")
            )?;
        } else {
            write!(
                output,
                "\x1b_Gm={};{}\x1b\\",
                usize::from(more),
                std::str::from_utf8(chunk).expect("base64 is ASCII")
            )?;
        }
    }
    // Keep the cursor in place, then return to column zero and reserve the
    // image's rows before Clap writes its help text.
    for _ in 0..IMAGE_HEIGHT_CELLS {
        output.write_all(b"\r\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{is_top_level_help, supports_kitty_graphics, write_logo};

    #[test]
    fn accepts_known_graphics_terminals() {
        assert!(supports_kitty_graphics(
            Some("kitty"),
            Some("xterm-kitty"),
            false,
            false
        ));
        assert!(supports_kitty_graphics(
            Some("WezTerm"),
            Some("xterm-256color"),
            false,
            false
        ));
        assert!(supports_kitty_graphics(
            Some("ghostty"),
            Some("xterm-ghostty"),
            false,
            false
        ));
    }

    #[test]
    fn rejects_plain_and_multiplexed_terminals() {
        for values in [
            (Some("kitty"), Some("dumb"), true, false),
            (Some("kitty"), Some("screen-256color"), false, false),
            (Some("kitty"), Some("xterm-kitty"), true, false),
            (Some("ghostty"), Some("xterm-ghostty"), false, true),
            (Some("other"), Some("xterm-256color"), false, false),
        ] {
            assert!(!supports_kitty_graphics(
                values.0, values.1, values.2, values.3
            ));
        }
    }

    #[test]
    fn recognizes_only_bare_top_level_help_requests() {
        assert!(is_top_level_help(&[]));
        assert!(is_top_level_help(&[OsString::from("help")]));
        assert!(is_top_level_help(&[OsString::from("--help")]));
        assert!(is_top_level_help(&[OsString::from("-h")]));
        assert!(!is_top_level_help(&[
            OsString::from("help"),
            OsString::from("pair")
        ]));
        assert!(!is_top_level_help(&[
            OsString::from("status"),
            OsString::from("--help")
        ]));
        assert!(!is_top_level_help(&[OsString::from("--version")]));
    }

    #[test]
    fn logo_uses_chunked_kitty_data_and_reserves_rows() {
        let mut rendered = Vec::new();
        write_logo(&mut rendered).unwrap();
        let rendered = String::from_utf8(rendered).unwrap();
        assert!(rendered.starts_with("\x1b_Ga=T,f=100,q=2,C=1,c=8,r=4,m=1;"));
        assert!(rendered.contains("\x1b_Gm=0;"));
        assert!(rendered.ends_with("\r\n\r\n\r\n\r\n"));
        let encoded = rendered
            .split("\x1b\\")
            .filter_map(|part| part.split_once(';').map(|(_, data)| data))
            .collect::<String>();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
        assert_eq!(
            decoded,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../assets/oshioki-cli.png"
            ))
        );
    }
}
