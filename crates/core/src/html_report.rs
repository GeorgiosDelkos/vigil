//! The HTML report: one self-contained page with every target's open findings and issues in
//! full, the confirmed fixes and the targets, for reading in a browser.
//!
//! It renders the same data as `vigil findings` and the popover ([`latest`], ranked by
//! [`popover_view`]), so it never disagrees with them. The page is one file with inline CSS
//! and a few lines of inline script for the Copy buttons; it loads nothing, and its Content
//! Security Policy forbids any request, so it works offline and cannot leak what it shows.
//!
//! Every text in it holds agent text or names from the target, so every one is HTML-escaped
//! ([`esc`]). Links go only to NVD (for a CVE id) or OSV.dev (for another advisory id), and
//! only for an id of a strict shape ([`advisory_link`]); anything else is plain text, the
//! agent's pull request URLs included.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use jiff::Timestamp;

use crate::config::Config;
use crate::lifecycle::FixState;
use crate::lifecycle::Latest;
use crate::lifecycle::StateError;
use crate::lifecycle::latest;
use crate::lifecycle::locked;
use crate::paths::DataDir;
use crate::popover::FixedListed;
use crate::popover::Listed;
use crate::popover::PopoverView;
use crate::popover::popover_view;

/// Writes the HTML report of every configured target to `<data dir>/report.html`, replacing
/// the last one, and returns its path.
///
/// Reads every target's newest report, the dismissals and the fix history, as [`latest`]
/// does. Does not open the page and does not touch the network.
///
/// # Errors
///
/// Fails when [`latest`] cannot read the state, or when the file cannot be written.
pub fn write_html_report(data_dir: &DataDir, config: &Config) -> Result<PathBuf, StateError> {
    let html = render(latest(data_dir, config)?, Timestamp::now());
    let path = data_dir.report_html_file();
    let write_err = |source| StateError::Write {
        path: path.clone(),
        source,
    };
    let dir = path
        .parent()
        .expect("the report file is inside the data directory");
    // Written under another name and renamed, so a browser never shows half a page, and
    // under the state lock, as the CLI and the app (or two clicks) may write it at once and
    // would share the partial file. A partial file a failed write leaves is replaced by the
    // next one. Not synced: the page is a view of other files and is written again on the
    // next request.
    let partial = dir.join(".report.html.partial");
    locked(data_dir, |_| {
        fs::create_dir_all(dir)
            .and_then(|()| fs::File::create(&partial))
            .and_then(|mut file| file.write_all(html.as_bytes()))
            .and_then(|()| fs::rename(&partial, &path))
            .map_err(write_err)
    })?;
    Ok(path)
}

/// The page for `latest`, generated at `now`.
fn render(latest: Vec<Latest>, now: Timestamp) -> String {
    let components: usize = latest.iter().map(|t| t.components).sum();
    let view = popover_view(latest);
    let mut out = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\n\
         <title>Vigil report</title>\n<style>{PLEX_CSS}{CSS}</style>\n</head>\n<body>\n<main>\n"
    );
    out.push_str(&head(&view, components, now));
    out.push_str(&numbers(&view));
    out.push_str(&exploited_callout(&view));
    out.push_str(&findings(&view));
    out.push_str(&targets_table(&view));
    out.push_str(&fixed_table(&view.fixed));
    out.push_str(&format!(
        "<footer class=\"rep-foot\"><span>Sources: OSV.dev (with the GitHub Advisory \
         Database), NVD and the CISA KEV catalog, as of each target's sweep.</span>\
         <span>Agent text is shown as plain text; links go only to NVD and OSV.dev. Generated \
         by Vigil on {}.</span></footer>\n",
        when(now)
    ));
    out.push_str(&format!(
        "</main>\n<script>{COPY_SCRIPT}</script>\n</body>\n</html>\n"
    ));
    out
}

/// The mark, the headline and when the page was made.
fn head(view: &PopoverView, components: usize, now: Timestamp) -> String {
    let sub = match &view.first_sweep_hint {
        Some(hint) => esc(hint),
        None => format!(
            "{} · {} checked",
            esc(&view.target_count),
            plural(components, "component")
        ),
    };
    let swept = view
        .last_swept
        .map_or(String::new(), |at| format!("<br>last sweep {}", when(at)));
    format!(
        "<header class=\"rep-head\">{}<div><h1>{}</h1><p>{sub}</p></div>\
         <div class=\"stamp\">generated {}{swept}</div></header>\n",
        MARK,
        esc(&view.headline),
        when(now)
    )
}

/// Vigil's mark: the tray icon's three-arm vortex (app/src-tauri/icons/src/mark.svg, drawn by
/// marks.py) on the report's tile, with the outer streaks in the findings' pink.
const MARK: &str = include_str!("html_report/mark.svg");

/// The row of key numbers; the first two glow when they are not zero.
fn numbers(view: &PopoverView) -> String {
    let cell = |n: usize, label: &str, hot: bool| {
        let class = if hot && n > 0 { " class=\"hot\"" } else { "" };
        format!("<div{class}><b>{n}</b><span>{label}</span></div>")
    };
    format!(
        "<section class=\"rep-kpis\">{}{}{}{}{}</section>\n",
        cell(view.needs_you, "need you", true),
        cell(view.exploited, "exploited in the wild", true),
        cell(view.findings.len(), "open in all", false),
        cell(view.fixed.len(), "fixed in 30 days", false),
        cell(view.dismissed, "dismissed", false),
    )
}

/// One line per finding exploited in the wild, saying what to run first; nothing when none
/// is.
fn exploited_callout(view: &PopoverView) -> String {
    let lines: Vec<String> = view
        .findings
        .iter()
        .filter(|f| f.open.known_exploited)
        .map(|f| {
            let open = &f.open;
            // A command reads as code; a manual fix's summary reads as prose.
            let first = match (open.commands.first(), open.fix.is_empty()) {
                (Some(command), _) => {
                    format!(" Fix it first: <code>{}</code>", esc(command))
                }
                (None, false) => format!(" Fix it first: {}.", esc(&open.fix)),
                (None, true) => String::new(),
            };
            format!(
                "<p><b>{}{} on {}</b> is affected by {}, which attackers are using now.{first}</p>",
                esc(&open.name),
                open.version
                    .as_ref()
                    .map_or(String::new(), |v| format!(" {}", esc(v))),
                esc(&f.target),
                advisory_links(&open.advisories),
            )
        })
        .collect();
    if lines.is_empty() {
        return String::new();
    }
    format!(
        "<section class=\"rep-alert\"><span class=\"kevpill\">Exploited</span><div>{}</div>\
         </section>\n",
        lines.concat()
    )
}

/// "Needs you", then "Lower"; or one line saying nothing is open.
fn findings(view: &PopoverView) -> String {
    if view.findings.is_empty() {
        let unswept = view.targets.iter().filter(|t| t.swept.is_none()).count();
        let text = match (view.all_clear, unswept) {
            (false, _) => {
                "No target has a sweep with a verdict yet, so nothing is known.".to_owned()
            }
            (true, 0) => "Nothing is open. Every target's newest sweep found nothing affected \
                          or risky."
                .to_owned(),
            (true, n) => format!(
                "Nothing is open in the swept targets; {} not swept yet.",
                plural(n, "target")
            ),
        };
        return format!("<section class=\"rep-clear\"><p>{text}</p></section>\n");
    }
    let (need, lower): (Vec<&Listed>, Vec<&Listed>) =
        view.findings.iter().partition(|f| f.needs_you);
    let mut out = String::new();
    for (title, group) in [("Needs you", need), ("Lower", lower)] {
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("<section><h2>{title}</h2>\n"));
        for (i, listed) in group.into_iter().enumerate() {
            // The worst finding that needs the user starts expanded, as in the mockup.
            out.push_str(&item(listed, listed.needs_you && i == 0));
        }
        out.push_str("</section>\n");
    }
    out
}

/// One finding or issue: a summary line that expands to everything its report keeps.
fn item(listed: &Listed, expanded: bool) -> String {
    let open = &listed.open;
    let severity = open.severity.to_string();
    let version = open
        .version
        .as_ref()
        .map_or(String::new(), |v| format!("<span>{}</span>", esc(v)));
    let exploited = if open.known_exploited {
        "<span class=\"sevlbl kev\">Exploited</span>"
    } else {
        ""
    };
    let kev_note = if open.known_exploited {
        " CISA lists it in its Known Exploited Vulnerabilities catalog."
    } else {
        ""
    };
    let mut body = format!(
        "<p class=\"why\">{}{kev_note}</p>{}",
        esc(&open.explanation),
        details_list(listed)
    );
    if !open.evidence.is_empty() {
        body.push_str(&format!("<div class=\"ev\">{}</div>", esc(&open.evidence)));
    }
    body.push_str(&fix_part(listed));
    format!(
        "<details class=\"f\"{}><summary><span class=\"dot {severity}\"></span>\
         <span class=\"t\">{}{version}</span><span class=\"w\">{}</span>\
         <span class=\"tags\">{exploited}<span class=\"sevlbl {severity}\">{severity}</span>\
         <span class=\"chev\">›</span></span></summary><div class=\"body\">{body}</div>\
         </details>\n",
        if expanded { " open" } else { "" },
        esc(&open.name),
        place(listed),
    )
}

/// "This Mac · lockfile ~/code/shop/package-lock.json", or the target alone for an issue.
fn place(listed: &Listed) -> String {
    if listed.open.place.is_empty() {
        esc(&listed.target)
    } else {
        format!("{} · {}", esc(&listed.target), esc(&listed.open.place))
    }
}

/// The definition list under a finding's explanation.
fn details_list(listed: &Listed) -> String {
    let open = &listed.open;
    let mut rows: Vec<(&str, String)> = Vec::new();
    if open.advisories.is_empty() {
        // An issue: no advisory, and its title is its subject ("setting x", "file y").
        rows.push(("Subject", esc(&open.title)));
    } else {
        let label = if open.advisories.len() == 1 {
            "Advisory"
        } else {
            "Advisories"
        };
        rows.push((label, advisory_links(&open.advisories)));
    }
    if let Some(version) = &open.version {
        rows.push(("Installed", format!("{} {}", esc(&open.name), esc(version))));
    }
    rows.push(("Where", place(listed)));
    if let Some(confidence) = open.confidence {
        rows.push(("Confidence", confidence.to_string()));
    }
    let seen = open.first_seen.map_or("not recorded".to_owned(), when);
    let new = if open.new {
        " (new in the last sweep)"
    } else {
        ""
    };
    rows.push(("First seen", format!("{seen}{new}")));
    if let Some(state) = &open.fix_state {
        rows.push(("Fix status", fix_status(state)));
    }
    rows.push(("Key", format!("<code>{}</code>", open.key)));
    let rows: String = rows
        .into_iter()
        .map(|(term, value)| format!("<dt>{term}</dt><dd>{value}</dd>"))
        .collect::<Vec<_>>()
        .concat();
    format!("<dl>{rows}</dl>")
}

/// What the fix history says, one line; the pull request URL is the agent's, so plain text.
fn fix_status(state: &FixState) -> String {
    match state {
        FixState::Reported {
            at,
            summary,
            pull_request,
        } => {
            let pull_request = pull_request.as_ref().map_or(String::new(), |url| {
                format!("; pull request <code>{}</code>", esc(url))
            });
            format!(
                "fix reported on {}: {}{pull_request}. The next sweep checks it.",
                when(*at),
                esc(summary)
            )
        }
        FixState::NotHeld { at } => format!("still found after a fix on {}", when(*at)),
    }
}

/// The fix: its summary, its steps, and each command with a Copy button.
fn fix_part(listed: &Listed) -> String {
    let open = &listed.open;
    let mut out = String::new();
    if !open.fix.is_empty() {
        out.push_str(&format!(
            "<p class=\"fixsum\"><b>Fix:</b> {}</p>",
            esc(&open.fix)
        ));
    }
    if !open.steps.is_empty() {
        let steps: String = open
            .steps
            .iter()
            .map(|s| format!("<li>{}</li>", esc(s)))
            .collect::<Vec<_>>()
            .concat();
        out.push_str(&format!("<ol class=\"steps\">{steps}</ol>"));
    }
    for command in &open.commands {
        out.push_str(&format!(
            "<div class=\"cmdl\"><code>{}</code><button type=\"button\">Copy</button></div>",
            esc(command)
        ));
    }
    out
}

/// One row per target.
fn targets_table(view: &PopoverView) -> String {
    let rows: String = view
        .targets
        .iter()
        .map(|t| {
            format!(
                "<tr><td><b>{}</b></td><td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
                esc(&t.label),
                esc(t.checked.as_deref().unwrap_or("not swept yet")),
                t.open,
                t.counts.critical,
                t.counts.high,
                t.counts.medium,
                t.counts.low,
                t.dismissed,
                t.swept.map_or("never".to_owned(), when),
            )
        })
        .collect::<Vec<_>>()
        .concat();
    format!(
        "<section><h2>Targets</h2><div class=\"scroll\"><table><thead><tr><th>Target</th>\
         <th>Checked</th><th>Open</th><th>Critical</th><th>High</th><th>Medium</th>\
         <th>Low</th><th>Dismissed</th><th>Swept</th></tr></thead><tbody>{rows}</tbody>\
         </table></div></section>\n"
    )
}

/// The fixes a later sweep confirmed in the last 30 days; nothing when there are none.
fn fixed_table(fixed: &[FixedListed]) -> String {
    if fixed.is_empty() {
        return String::new();
    }
    let rows: String = fixed
        .iter()
        .map(|f| {
            let pull_request = f.fixed.pull_request.as_ref().map_or(String::new(), |url| {
                format!("<br><code>{}</code>", esc(url))
            });
            format!(
                "<tr><td><b>{}</b></td><td>{}</td><td>{}{pull_request}</td><td>{}</td></tr>",
                esc(&f.fixed.title),
                esc(&f.target),
                esc(&f.fixed.summary),
                when(f.fixed.fixed_at)
            )
        })
        .collect::<Vec<_>>()
        .concat();
    format!(
        "<section><h2>Fixed in the last 30 days</h2><div class=\"scroll\"><table><thead><tr>\
         <th>Finding</th><th>Target</th><th>What the agent did</th><th>Fixed</th></tr>\
         </thead><tbody>{rows}</tbody></table></div></section>\n"
    )
}

/// The advisory ids, comma-separated, each a link when [`advisory_link`] allows one.
fn advisory_links(ids: &[String]) -> String {
    ids.iter()
        .map(|id| advisory_link(id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `id` as a link to NVD when it is a CVE id (`CVE-2024-3094`), to OSV.dev when it is
/// another advisory id of a strict shape (`GHSA-xxxx-xxxx-xxxx`, `RUSTSEC-2024-0001`,
/// `RHSA-2024:1234`), and as plain text otherwise. The shape check means an id can never
/// change where the link goes; it is escaped anyway.
fn advisory_link(id: &str) -> String {
    let url = if is_cve(id) {
        format!("https://nvd.nist.gov/vuln/detail/{id}")
    } else if is_osv_id(id) {
        format!("https://osv.dev/vulnerability/{id}")
    } else {
        return esc(id);
    };
    format!(
        "<a href=\"{}\" referrerpolicy=\"no-referrer\">{}</a>",
        esc(&url),
        esc(id)
    )
}

/// `CVE-`, a four-digit year, `-`, and 4 to 20 digits. 20 is arbitrary: CVE numbers in use
/// have at most 7.
fn is_cve(id: &str) -> bool {
    let Some((year, number)) = id
        .strip_prefix("CVE-")
        .and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    year.len() == 4 && digits(year) && (4..=20).contains(&number.len()) && digits(number)
}

/// An ASCII letter, then letters, digits, `-`, `_`, `.` and `:`, with at least one `-`, at
/// most 64 bytes: the shape of OSV ids. It cannot hold `/`, `?`, `#`, `%` or a dot segment,
/// so the URL stays on the OSV.dev page for that id. 64 is arbitrary: the longest ids in use
/// are about 40.
fn is_osv_id(id: &str) -> bool {
    id.len() <= 64
        && id.starts_with(|c: char| c.is_ascii_alphabetic())
        && id.contains('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// `text` with the five characters that can end an HTML text or attribute value escaped.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A time as the page shows it: "9 Nov 2026, 13:48 UTC". UTC, because the core does not read
/// the system's time zone (jiff's `tz-system` feature is off).
fn when(at: Timestamp) -> String {
    at.strftime("%-d %b %Y, %H:%M UTC").to_string()
}

/// "1 component", "3 components".
fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// No request of any kind: inline styles, the embedded font, an inline SVG, and only the one
/// script whose hash is here. The hash is the base64 SHA-256 of [`COPY_SCRIPT`]; a test
/// recomputes it.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; \
                   script-src 'sha256-2puN7X5gHhznz7AN+jqHuycIANGj9d/cqyTyUaB4TJ0='; \
                   base-uri 'none'; form-action 'none'";

/// Selects and copies the command beside a Copy button. `execCommand("copy")` comes first, while
/// the click still counts as the user's gesture (Safari refuses it later); the clipboard API,
/// which needs a secure context that a `file:` page may not be, is the fallback. When both
/// fail, the command stays selected for the user to copy.
const COPY_SCRIPT: &str = r#"
document.addEventListener("click", (event) => {
  const button = event.target.closest(".cmdl button");
  if (!button) return;
  const code = button.previousElementSibling;
  const done = () => {
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = "Copy"; }, 1500);
  };
  const range = document.createRange();
  range.selectNodeContents(code);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
  if (document.execCommand("copy")) done();
  else if (navigator.clipboard) navigator.clipboard.writeText(code.textContent).then(done);
});
"#;

/// IBM Plex Sans, the app's one typeface, as `@font-face` rules with the font files inlined:
/// the page is opened from disk and its CSP allows no request, so the font travels inside it
/// (about 155 kB). The file is a licence comment on the first line (the copyright and OFL
/// notice), then the `@font-face` rules of `app/ui/src/style.css`, one line each, with every
/// `url()` replaced by that file's `data:font/woff2;base64,` URL. Regenerate it that way after
/// changing the fonts; `the_report_font_is_the_app_s` checks every rule's family, weight,
/// unicode-range and inlined file against style.css, the rule count, and the notice.
const PLEX_CSS: &str = include_str!("html_report/plex.css");

/// The approved mockup's report styles, dark only: the night ground with faint violet and cyan
/// light, glass panels and the neon severity colours, all text in IBM Plex Sans.
const CSS: &str = r#"
:root {
  color-scheme: dark;
  --font: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
}
* { box-sizing: border-box; }
html { background: #08070f; }
body { margin: 0; color: #e6e9f5; font: 15px/1.6 var(--font); min-height: 100vh; background:
  radial-gradient(60% 40% at 0% 0%, rgba(155,92,255,.10), transparent 70%),
  radial-gradient(50% 35% at 100% 10%, rgba(62,240,255,.07), transparent 70%), #08070f;
  background-attachment: fixed; }
main { max-width: 1060px; margin: 0 auto; padding: 40px 24px 56px; display: grid; gap: 34px; }
p { margin: 0; }
/* Commands, keys and links are <code>, in the one typeface rather than the default mono. */
code { font-family: var(--font); }
.rep-head { display: grid; grid-template-columns: auto 1fr auto; gap: 18px; align-items: center; }
.mark rect { fill: #12162a; }
.mark path { stroke: #8fa2ff; }
.mark path.edge { stroke: #ff2e88; }
.rep-head h1 { margin: 0; font: 700 30px/1.05 var(--font); letter-spacing: -.02em;
  color: #f4f6ff; }
.rep-head p { color: #8e96ad; font-size: 14px; }
.rep-head .stamp { text-align: right; font: 12px/1.5 var(--font); color: #8e96ad; }
.rep-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1px;
  background: rgba(255,255,255,.07); border-radius: 14px; overflow: hidden; }
.rep-kpis div { background: #100f1a; padding: 16px 18px; display: grid; gap: 2px; }
.rep-kpis b { font: 600 30px/1 var(--font); letter-spacing: -.02em; color: #f4f6ff;
  font-variant-numeric: tabular-nums; }
.rep-kpis span { font-size: 12.5px; color: #8e96ad; }
.rep-kpis .hot b { color: #ff2e88; text-shadow: 0 0 16px rgba(255,46,136,.55); }
.rep-alert { border-radius: 14px; padding: 16px 20px; display: flex; gap: 14px;
  align-items: flex-start; background: rgba(255,46,136,.08); color: #ffd3e2;
  box-shadow: inset 0 0 0 1px rgba(255,46,136,.45), 0 0 30px -12px rgba(255,46,136,.7); }
.rep-alert div { display: grid; gap: 6px; }
.rep-alert b { font-weight: 600; }
.rep-alert a { color: #ffd3e2; }
.kevpill { font: 700 9.5px/1 var(--font); letter-spacing: .08em; text-transform: uppercase;
  color: #fff; background: #ff4d6d; border-radius: 5px; padding: 4px 6px; margin-top: 3px;
  box-shadow: 0 0 14px -2px rgba(255,77,109,.8); }
.rep-clear p { border-radius: 14px; padding: 16px 20px; color: #c9f5dc;
  background: rgba(79,209,139,.08); box-shadow: inset 0 0 0 1px rgba(79,209,139,.35); }
h2 { margin: 0 0 12px; font: 600 13px var(--font); letter-spacing: .1em; text-transform: uppercase;
  color: #7f88a3; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.critical { background: #ff3b5c; box-shadow: 0 0 8px #ff3b5c; }
.dot.high { background: #ff8a1f; box-shadow: 0 0 8px #ff8a1f; }
.dot.medium { background: #ffe14a; box-shadow: 0 0 8px #ffe14a; }
.dot.low { background: #8fa2ff; }
.f { border-radius: 14px; margin-bottom: 10px; background: rgba(255,255,255,.035);
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); }
.f summary { list-style: none; cursor: pointer; display: grid;
  grid-template-columns: 12px minmax(0, auto) 1fr auto; gap: 14px; align-items: center;
  padding: 14px 18px; }
.f summary::-webkit-details-marker { display: none; }
.f summary .t { font-weight: 600; }
.f summary .t span { font: 13px var(--font); color: #8e96ad; margin-left: 6px; font-weight: 400; }
.f summary .w { color: #8e96ad; font-size: 13px; overflow-wrap: anywhere; }
.f summary .tags { display: flex; gap: 8px; align-items: center; }
.f summary .chev { color: #5d6579; transition: transform .2s; }
.f[open] summary .chev { transform: rotate(90deg); }
.f .body { padding: 0 18px 18px 44px; display: grid; gap: 14px; }
.f .body dl { display: grid; grid-template-columns: 120px 1fr; gap: 6px 16px; margin: 0;
  font-size: 14px; }
.f .body dt { color: #8e96ad; }
.f .body dd { margin: 0; overflow-wrap: anywhere; }
.f .body a { color: #3ef0ff; text-decoration: none; border-bottom: 1px solid rgba(62,240,255,.35); }
.f .why { max-width: 72ch; color: #cdd3e4; }
.f .ev { font: 12.5px/1.55 var(--font); border-radius: 10px; padding: 12px 14px; color: #b5bdd3;
  background: rgba(0,0,0,.35); box-shadow: inset 0 0 0 1px rgba(255,255,255,.06);
  overflow-wrap: anywhere; }
.f .fixsum { color: #cdd3e4; }
.f .steps { margin: 0; padding-left: 20px; color: #cdd3e4; }
.f .cmdl { display: flex; gap: 10px; align-items: center; font: 13px var(--font);
  border-radius: 10px; padding: 10px 14px; background: #050409; color: #dfe6ff;
  box-shadow: inset 0 0 0 1px rgba(62,240,255,.25); }
.f .cmdl::before { content: "$"; color: #6b7389; }
.f .cmdl code { overflow-wrap: anywhere; }
.f .cmdl button { margin-left: auto; font: 500 12px var(--font); border: 0; border-radius: 6px;
  padding: 4px 9px; cursor: pointer; background: rgba(62,240,255,.12); color: #8ff6ff; }
.sevlbl { font: 600 11px var(--font); letter-spacing: .06em; text-transform: uppercase;
  padding: 3px 8px; border-radius: 6px; }
.sevlbl.critical { background: rgba(255,59,92,.16); color: #ff8098; }
.sevlbl.high { background: rgba(255,138,31,.14); color: #ffae66; }
.sevlbl.medium { background: rgba(255,225,74,.12); color: #ffe57a; }
.sevlbl.low { background: rgba(143,162,255,.12); color: #b3c0ff; }
.sevlbl.kev { background: rgba(255,46,136,.16); color: #ff7bb0;
  box-shadow: 0 0 12px -4px rgba(255,46,136,.8); }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; border-radius: 14px;
  overflow: hidden; background: rgba(255,255,255,.03);
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); }
th, td { text-align: left; padding: 11px 16px; border-bottom: 1px solid rgba(255,255,255,.06);
  vertical-align: top; }
th { font: 600 12px var(--font); color: #8e96ad; background: rgba(255,255,255,.04); }
td.num { font-variant-numeric: tabular-nums; }
.rep-foot { font-size: 13px; color: #7f88a3; display: grid; gap: 4px; }
@media (max-width: 640px) {
  .rep-head { grid-template-columns: auto 1fr; }
  .rep-head .stamp { grid-column: 1 / -1; text-align: left; }
  .f summary { grid-template-columns: 12px 1fr auto; }
  .f summary .w { grid-column: 2 / -1; grid-row: 2; }
  .f .body { padding-left: 18px; }
  .f .body dl { grid-template-columns: 1fr; }
}
"#;

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::process::Stdio;

    use proptest::prelude::*;

    use super::*;
    use crate::findings::Confidence;
    use crate::findings::Severity;
    use crate::lifecycle::Fixed;
    use crate::lifecycle::Open;

    fn at(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn open(key: u64, severity: Severity, exploited: bool) -> Open {
        Open {
            key: format!("{key:016x}").parse().unwrap(),
            severity,
            title: format!("finding {key}"),
            name: format!("pkg{key}"),
            version: Some("1.0.0".to_owned()),
            advisories: vec!["CVE-2024-3094".to_owned()],
            place: "Homebrew".to_owned(),
            known_exploited: exploited,
            confidence: None,
            evidence: String::new(),
            explanation: "It is affected.".to_owned(),
            fix: "upgrade it".to_owned(),
            steps: Vec::new(),
            commands: vec![format!("brew upgrade pkg{key}")],
            first_seen: Some(at("2026-11-01T00:00:00Z")),
            new: false,
            fix_state: None,
        }
    }

    fn mac(open: Vec<Open>) -> Latest {
        Latest {
            target: "mac".to_owned(),
            swept: Some(at("2026-11-09T13:48:00Z")),
            components: 139,
            open,
            fixed: Vec::new(),
            dismissed: 0,
        }
    }

    fn page(latest: Vec<Latest>) -> String {
        render(latest, at("2026-11-09T14:00:00Z"))
    }

    #[test]
    fn a_zero_does_not_glow() {
        let html = page(vec![mac(vec![open(1, Severity::Low, false)])]);
        assert!(html.contains("<div><b>0</b><span>exploited in the wild</span>"));
    }

    #[test]
    fn the_fix_line_shows_only_when_there_is_a_fix() {
        let with = page(vec![mac(vec![open(1, Severity::High, false)])]);
        assert!(with.contains("<b>Fix:</b> upgrade it"));

        let mut bare = open(1, Severity::High, false);
        bare.fix = String::new();
        let without = page(vec![mac(vec![bare])]);
        assert!(!without.contains("<b>Fix:</b>"));
    }

    #[test]
    fn the_report_font_is_the_app_s() {
        // Every @font-face rule of the app's style.css, with the same weight and unicode-range
        // and its file inlined, so the two cannot drift apart.
        let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/ui/src");
        let style = std::fs::read_to_string(ui.join("style.css")).unwrap();
        let faces: Vec<&str> = style.split("@font-face {").skip(1).collect();
        assert_eq!(faces.len(), 8, "four weights, Latin1 and Pi");
        assert_eq!(
            PLEX_CSS.matches("@font-face").count(),
            faces.len(),
            "plex.css has a rule style.css lacks"
        );
        for face in faces {
            let face = &face[..face.find('}').unwrap()];
            let value = |name: &str| {
                let start = face.find(name).unwrap() + name.len();
                let end = start + face[start..].find(';').unwrap();
                face[start..end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let file = value("src: url(\"./");
            let file = &file[..file.find('"').unwrap()];
            let out = Command::new("/usr/bin/openssl")
                .args(["base64", "-A", "-in"])
                .arg(ui.join(file))
                .output()
                .expect("macOS ships /usr/bin/openssl");
            assert!(out.status.success(), "openssl base64 {file}");
            let encoded = String::from_utf8(out.stdout).unwrap();
            let rule = format!(
                "font-family: {}; font-weight: {}; \
                 src: url(\"data:font/woff2;base64,{}\") format(\"woff2\"); unicode-range: {};",
                value("font-family: "),
                value("font-weight: "),
                encoded.trim(),
                value("unicode-range:")
            );
            assert!(PLEX_CSS.contains(&rule), "{file} differs from style.css");
        }
        assert!(PLEX_CSS.starts_with("/* IBM Plex Sans: Copyright"));
        assert!(page(vec![mac(Vec::new())]).contains(PLEX_CSS));
    }

    #[test]
    fn agent_text_stays_text() {
        let mut o = open(1, Severity::High, false);
        o.explanation = "<script>alert('x')</script> & \"q\"".to_owned();
        o.evidence = "</div><img src=x onerror=alert(1)>".to_owned();
        o.steps = vec!["<b>bold</b>".to_owned()];
        o.commands = vec!["echo '</code><script>'".to_owned()];
        let html = page(vec![mac(vec![o])]);
        assert_eq!(html.matches("<script").count(), 1, "only the Copy script");
        assert!(
            html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;q&quot;")
        );
        assert!(html.contains("&lt;/div&gt;&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!html.contains("<img"));
        assert!(html.contains("<li>&lt;b&gt;bold&lt;/b&gt;</li>"));
        assert!(html.contains("<code>echo &#39;&lt;/code&gt;&lt;script&gt;&#39;</code>"));
    }

    #[test]
    fn advisories_link_only_for_ids_of_a_safe_shape() {
        assert_eq!(
            advisory_link("CVE-2024-3094"),
            "<a href=\"https://nvd.nist.gov/vuln/detail/CVE-2024-3094\" \
             referrerpolicy=\"no-referrer\">\
             CVE-2024-3094</a>"
        );
        for id in ["GHSA-c2qf-rxjj-qqgw", "RUSTSEC-2024-0001", "RHSA-2024:1234"] {
            assert_eq!(
                advisory_link(id),
                format!(
                    "<a href=\"https://osv.dev/vulnerability/{id}\" \
                     referrerpolicy=\"no-referrer\">{id}</a>"
                )
            );
        }
        for id in [
            "",
            "GHSA",
            "1-2",
            "GHSA-x/../../evil",
            "GHSA-x?y",
            "GHSA-x#y",
            "GHSA-%2e",
            "GHSA-x y",
            "GHSA-\"onmouseover=\"x",
            "javascript-\u{e9}",
        ] {
            let shown = advisory_link(id);
            assert!(!shown.contains("<a"), "{id:?} must not link: {shown}");
            assert_eq!(shown, esc(id));
        }
        for id in ["CVE-2024-1", "CVE-24-12345", "CVE-2024-12a45"] {
            assert!(!advisory_link(id).contains("nvd"), "{id} is not a CVE id");
        }
        let long = format!("GHSA-{}", "a".repeat(60));
        assert!(!advisory_link(&long).contains("<a"), "longer than 64");

        let mut o = open(1, Severity::Low, false);
        o.advisories = vec!["CVE-2024-3094".to_owned(), "<x>-1".to_owned()];
        let html = page(vec![mac(vec![o])]);
        assert!(html.contains(
            "<dt>Advisories</dt><dd><a href=\"https://nvd.nist.gov/vuln/detail/CVE-2024-3094\" \
             referrerpolicy=\"no-referrer\">\
             CVE-2024-3094</a>, &lt;x&gt;-1</dd>"
        ));
    }

    proptest! {
        #[test]
        fn escaped_text_cannot_end_a_text_or_attribute(text in any::<String>()) {
            let out = esc(&text);
            prop_assert!(!out.contains(['<', '>', '"', '\'']));
            prop_assert_eq!(
                out.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
                    .replace("&#39;", "'").replace("&amp;", "&"),
                text
            );
        }

        #[test]
        fn a_link_is_the_page_of_its_id_and_nothing_else(
            id in "(CVE-[0-9]{4}-[0-9]{3,6}|[A-Za-z][A-Za-z0-9._:/?#%\"' <>&-]{0,70})"
        ) {
            let shown = advisory_link(&id);
            if shown.starts_with("<a ") {
                prop_assert!(!id.contains(['/', '?', '#', '%', '"', '\'', ' ', '<', '>', '&']));
                let base = if is_cve(&id) {
                    "https://nvd.nist.gov/vuln/detail/"
                } else {
                    "https://osv.dev/vulnerability/"
                };
                prop_assert_eq!(
                    shown,
                    format!("<a href=\"{base}{id}\" referrerpolicy=\"no-referrer\">{id}</a>")
                );
            } else {
                prop_assert_eq!(shown, esc(&id));
            }
        }
    }

    #[test]
    fn every_text_from_the_agent_or_the_target_is_escaped() {
        let evil = "<x\"'>";
        let reported = Open {
            title: evil.to_owned(),
            name: evil.to_owned(),
            version: Some(evil.to_owned()),
            advisories: vec![evil.to_owned()],
            place: evil.to_owned(),
            evidence: evil.to_owned(),
            explanation: evil.to_owned(),
            fix: evil.to_owned(),
            steps: vec![evil.to_owned()],
            commands: Vec::new(),
            fix_state: Some(FixState::Reported {
                at: at("2026-11-08T00:00:00Z"),
                summary: evil.to_owned(),
                pull_request: Some(evil.to_owned()),
            }),
            ..open(1, Severity::High, true)
        };
        let issue = Open {
            title: evil.to_owned(),
            advisories: Vec::new(),
            place: String::new(),
            ..open(2, Severity::Low, false)
        };
        let mut target = mac(vec![reported, issue]);
        target.target = format!("github:{evil}");
        target.fixed = vec![Fixed {
            key: "0000000000000009".parse().unwrap(),
            title: evil.to_owned(),
            fixed_at: at("2026-11-08T10:00:00Z"),
            summary: evil.to_owned(),
            pull_request: Some(evil.to_owned()),
        }];
        let html = page(vec![target]);
        assert!(!html.contains("<x"), "{html}");
        assert!(!html.contains("x\"'"));
        // The callout, the summary line, the advisory, Installed, Where, the evidence, the fix
        // and its step, the fix status (summary and pull request), the issue's subject and
        // the targets, and the fixed row (title, target, summary and pull request).
        assert!(html.matches("&lt;x&quot;&#39;&gt;").count() >= 20);
        assert_eq!(html.matches("<script").count(), 1);
    }

    #[test]
    fn each_finding_lists_what_its_report_keeps_and_an_issue_its_subject() {
        let mut reported = open(1, Severity::High, false);
        reported.confidence = Some(Confidence::Likely);
        reported.new = true;
        reported.fix_state = Some(FixState::Reported {
            at: at("2026-11-08T00:00:00Z"),
            summary: "upgraded".to_owned(),
            pull_request: Some("https://github.com/o/r/pull/7".to_owned()),
        });
        let mut not_held = open(2, Severity::High, false);
        not_held.first_seen = None;
        not_held.fix_state = Some(FixState::NotHeld {
            at: at("2026-11-07T00:00:00Z"),
        });
        let issue = Open {
            version: None,
            advisories: Vec::new(),
            place: String::new(),
            title: "file github/workflows/ci.yml".to_owned(),
            ..open(3, Severity::Low, false)
        };
        let html = page(vec![mac(vec![reported, not_held, issue])]);
        let item = |n: usize| {
            let from = html.find(&format!("pkg{n}")).unwrap();
            let to = html[from..].find("</details>").unwrap();
            &html[from..from + to]
        };
        assert!(item(1).contains("<dt>Confidence</dt><dd>likely</dd>"));
        assert!(
            item(1)
                .contains("<dt>First seen</dt><dd>1 Nov 2026, 00:00 UTC (new in the last sweep)")
        );
        assert!(item(1).contains(
            "<dt>Fix status</dt><dd>fix reported on 8 Nov 2026, 00:00 UTC: upgraded; pull \
             request <code>https://github.com/o/r/pull/7</code>. The next sweep \
             checks it.</dd>"
        ));
        assert!(item(1).contains("<dt>Installed</dt><dd>pkg1 1.0.0</dd>"));
        assert!(item(1).contains("<dt>Where</dt><dd>This Mac · Homebrew</dd>"));
        assert!(item(1).contains("<dt>Key</dt><dd><code>0000000000000001"));
        assert!(item(2).contains("<dt>First seen</dt><dd>not recorded</dd>"));
        assert!(item(2).contains(
            "<dt>Fix status</dt><dd>still found after a fix on 7 Nov 2026, 00:00 UTC</dd>"
        ));
        assert!(!item(2).contains("Confidence"));
        let issue = item(3);
        assert!(issue.contains("<dt>Subject</dt><dd>file github/workflows/ci.yml</dd>"));
        assert!(issue.contains("<dt>Where</dt><dd>This Mac</dd>"));
        for absent in [
            "<dt>Advisor",
            "<dt>Installed",
            "<dt>Confidence",
            "<dt>Fix status",
        ] {
            assert!(!issue.contains(absent), "{absent}");
        }
    }

    #[test]
    fn exploited_findings_get_the_callout_and_others_do_not() {
        let html = page(vec![mac(vec![open(1, Severity::Medium, false)])]);
        assert!(!html.contains("class=\"rep-alert\""));
        assert!(!html.contains("sevlbl kev"));

        let mut kev = open(2, Severity::Medium, true);
        kev.commands = vec!["brew upgrade webp".to_owned(), "second".to_owned()];
        let html = page(vec![mac(vec![open(1, Severity::Low, false), kev])]);
        assert_eq!(html.matches("class=\"rep-alert\"").count(), 1);
        assert!(html.contains(
            "<p><b>pkg2 1.0.0 on This Mac</b> is affected by \
             <a href=\"https://nvd.nist.gov/vuln/detail/CVE-2024-3094\" \
             referrerpolicy=\"no-referrer\">CVE-2024-3094</a>, \
             which attackers are using now. Fix it first: \
             <code>brew upgrade webp</code></p>"
        ));
        assert_eq!(html.matches("sevlbl kev").count(), 1, "only on pkg2");

        let mut bare = open(3, Severity::Low, true);
        bare.commands = Vec::new();
        bare.fix = String::new();
        let html = page(vec![mac(vec![bare])]);
        assert!(
            html.contains("which attackers are using now.</p>"),
            "no empty fix"
        );
        assert!(!html.contains("Fix it first"));

        let mut manual = open(4, Severity::Low, true);
        manual.commands = Vec::new();
        manual.fix = "<Upgrade> the app".to_owned();
        let html = page(vec![mac(vec![manual])]);
        assert!(html.contains("using now. Fix it first: &lt;Upgrade&gt; the app.</p>"));
        assert!(html.contains("<div class=\"hot\"><b>1</b><span>exploited in the wild</span>"));
    }

    #[test]
    fn findings_that_need_the_user_come_first_and_the_rest_under_lower() {
        let issue = Open {
            version: None,
            advisories: Vec::new(),
            place: String::new(),
            title: "setting default_branch_protection".to_owned(),
            ..open(3, Severity::Low, false)
        };
        let mut high = open(1, Severity::High, false);
        high.evidence = "4.1 < 4.2".to_owned();
        high.steps = vec!["upgrade".to_owned()];
        let html = page(vec![mac(vec![
            high,
            open(2, Severity::Medium, false),
            issue,
        ])]);
        let need = html
            .find("<h2>Needs you</h2>")
            .expect("a high finding needs you");
        let lower = html.find("<h2>Lower</h2>").expect("the rest are lower");
        let [one, two, three] = ["pkg1", "pkg2", "pkg3"].map(|n| html.find(n).unwrap());
        assert!(need < one && one < lower && lower < two && two < three);
        assert!(
            html.contains("<details class=\"f\" open>"),
            "the first that needs you"
        );
        assert_eq!(html.matches("<details class=\"f\" open>").count(), 1);
        assert!(html.contains("<div class=\"ev\">4.1 &lt; 4.2</div>"));
        assert!(html.contains("<ol class=\"steps\"><li>upgrade</li></ol>"));
        assert!(html.contains("<dt>Subject</dt><dd>setting default_branch_protection</dd>"));
        assert!(html.contains("<h1>1 finding needs you</h1>"));
        assert!(html.contains("<dt>First seen</dt><dd>1 Nov 2026, 00:00 UTC</dd>"));
    }

    #[test]
    fn a_swept_target_with_nothing_open_reads_all_clear() {
        let html = page(vec![mac(Vec::new())]);
        assert!(html.contains("<h1>All clear</h1>"));
        assert!(html.contains("Nothing is open."));
        assert!(!html.contains("<h2>Needs you</h2>") && !html.contains("<h2>Lower</h2>"));
        assert!(html.contains("<p>1 target · 139 components checked</p>"));
        assert!(html.contains("<td>139 components checked</td>"));

        let mut never = mac(Vec::new());
        never.swept = None;
        let mut repo = mac(Vec::new());
        repo.target = "github:o/r".to_owned();
        repo.swept = None;
        let html = page(vec![mac(Vec::new()), repo]);
        assert!(html.contains("Nothing is open in the swept targets; 1 target not swept yet."));

        let html = page(vec![never]);
        assert!(html.contains("<h1>Not swept yet</h1>"));
        assert!(html.contains("No target has a sweep with a verdict yet"));
        assert!(html.contains("<td>not swept yet</td>"));
    }

    #[test]
    fn fixed_and_dismissed_findings_are_shown() {
        let mut target = mac(Vec::new());
        assert!(!page(vec![mac(Vec::new())]).contains("Fixed in the last 30 days"));
        target.dismissed = 2;
        target.fixed = vec![Fixed {
            key: "0000000000000009".parse().unwrap(),
            title: "zlib <1.3".to_owned(),
            fixed_at: at("2026-11-08T10:00:00Z"),
            summary: "upgraded zlib".to_owned(),
            pull_request: Some("https://github.com/o/r/pull/7\"><x>".to_owned()),
        }];
        let html = page(vec![target]);
        assert!(html.contains("<h2>Fixed in the last 30 days</h2>"));
        assert!(html.contains(
            "<tr><td><b>zlib &lt;1.3</b></td><td>This Mac</td><td>upgraded zlib<br>\
             <code>https://github.com/o/r/pull/7&quot;&gt;&lt;x&gt;</code></td>\
             <td>8 Nov 2026, 10:00 UTC</td></tr>"
        ));
        assert!(html.contains("<div><b>2</b><span>dismissed</span></div>"));
        assert!(html.contains("<div><b>1</b><span>fixed in 30 days</span></div>"));
        assert!(html.contains("<td class=\"num\">2</td><td>9 Nov 2026, 13:48 UTC</td>"));
    }

    #[test]
    fn the_page_loads_nothing_and_allows_only_its_own_script() {
        let html = page(vec![mac(vec![open(1, Severity::High, true)])]);
        // The font is the one thing with a URL, and every one of its URLs is inline data.
        assert_eq!(
            PLEX_CSS.matches("url(").count(),
            PLEX_CSS.matches("url(\"data:font/woff2;base64,").count()
        );
        let rest = html.replace(PLEX_CSS, "");
        for needle in ["src=", "<link", "@import", "url(", "http://"] {
            assert!(!rest.contains(needle), "{needle}");
        }
        let hrefs: Vec<&str> = html.split("href=\"").skip(1).collect();
        assert_eq!(
            hrefs.len(),
            2,
            "the advisory, in the callout and in the finding"
        );
        for href in hrefs {
            assert!(
                href.starts_with("https://nvd.nist.gov/") || href.starts_with("https://osv.dev/")
            );
        }

        // The CSP names the script by its hash; recompute it so an edit to the script cannot
        // leave the Copy buttons silently blocked.
        let mut openssl = Command::new("/usr/bin/openssl")
            .args(["dgst", "-sha256", "-binary"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("macOS ships /usr/bin/openssl");
        openssl
            .stdin
            .take()
            .unwrap()
            .write_all(COPY_SCRIPT.as_bytes())
            .unwrap();
        let digest = openssl.wait_with_output().unwrap().stdout;
        let mut base64 = Command::new("/usr/bin/openssl")
            .arg("base64")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        base64.stdin.take().unwrap().write_all(&digest).unwrap();
        let hash = String::from_utf8(base64.wait_with_output().unwrap().stdout).unwrap();
        assert!(
            CSP.contains(&format!("script-src 'sha256-{}'", hash.trim())),
            "update the hash in CSP to {}",
            hash.trim()
        );
        assert!(html.contains(&format!("content=\"{CSP}\"")));
    }

    #[test]
    fn write_html_report_replaces_the_file_in_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = DataDir::new(tmp.path().join("data"));
        let config_path = tmp.path().join("config.toml");
        fs::write(&config_path, "").unwrap();
        let config = Config::load(&config_path, tmp.path()).unwrap();
        let path = write_html_report(&data_dir, &config).unwrap();
        assert_eq!(path, tmp.path().join("data/report.html"));
        fs::write(&path, "old").unwrap();
        write_html_report(&data_dir, &config).unwrap();
        let html = fs::read_to_string(&path).unwrap();
        assert!(html.starts_with("<!doctype html>") && html.contains("Not swept yet"));
        assert!(
            !tmp.path().join("data/.report.html.partial").exists(),
            "renamed into place"
        );
    }
}
