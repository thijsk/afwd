//! The AFWD specification, `spec/afwd-spec.txt`, laid out as an RFC: pages of 58 lines
//! with a running header and footer, and a table of contents with page numbers. It is
//! served as plain text and as HTML with links to sections, references and URLs.

use std::{collections::HashSet, fmt::Write, sync::LazyLock};

const SOURCE: &str = include_str!("../../../spec/afwd-spec.txt");

/// Lines per page, including the header and footer.
const PAGE_LINES: usize = 58;
const WIDTH: usize = 72;
/// The first page has no running header.
const FIRST_PAGE_BODY: usize = PAGE_LINES - 3;
const PAGE_BODY: usize = PAGE_LINES - 6;
/// Blocks this short are moved to the next page whole instead of being split.
const KEEP_TOGETHER: usize = 6;

pub static SPEC: LazyLock<Spec> = LazyLock::new(|| Spec::parse(SOURCE));

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Text,
    /// A section heading; its text starts in column 0.
    Heading,
    /// A table of contents entry, pointing at the heading with the same index.
    Toc(usize),
    Header,
    Footer,
}

#[derive(Clone, Debug)]
struct Line {
    text: String,
    kind: Kind,
}

#[derive(Debug)]
struct Block {
    lines: Vec<Line>,
    blank_before: usize,
}

impl Block {
    fn is_heading(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].kind == Kind::Heading
    }

    /// Figures (indented artwork, tables) are not split unless they exceed a page.
    fn is_figure(&self) -> bool {
        self.lines.iter().all(|line| {
            line.text.starts_with("     ")
                || line.text.starts_with("   +")
                || line.text.starts_with("   |")
        })
    }
}

/// A section heading and the anchor it gets in HTML.
#[derive(Debug)]
struct Heading {
    text: String,
    anchor: String,
    /// Listed in the table of contents, at this nesting level.
    toc_level: Option<usize>,
}

pub struct Spec {
    text: String,
    html: String,
}

impl Spec {
    /// The paginated plain text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The pages as HTML `<pre>` elements, for the spec page.
    pub fn html(&self) -> &str {
        &self.html
    }

    fn parse(source: &str) -> Self {
        let (settings, lines) = read_source(source);
        let headings = find_headings(&lines);

        // The table of contents takes the same number of lines whatever its page
        // numbers are, so a first layout gives the page of every heading.
        let draft = layout(&blocks(&lines, &headings, &vec![0; headings.len()]));
        let pages = heading_pages(&draft, &headings);
        let pages = layout(&blocks(&lines, &headings, &pages));

        let pages = decorate(pages, &settings);
        let text = pages
            .iter()
            .map(|page| {
                page.iter()
                    .map(|line| line.text.trim_end())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect::<Vec<_>>()
            .join("\n\u{c}\n")
            + "\n";
        let html = render_html(&pages, &headings, &references(&lines));
        Self { text, html }
    }
}

struct Settings {
    header: [String; 3],
    footer: [String; 2],
}

/// Splits off the `%%` lines and reads the `%% key: value` settings among them.
fn read_source(source: &str) -> (Settings, Vec<String>) {
    let get = |key: &str| {
        source
            .lines()
            .filter_map(|line| line.strip_prefix("%%"))
            .find_map(|line| line.trim().strip_prefix(key)?.strip_prefix(':'))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    };
    let settings = Settings {
        header: [
            get("header-left"),
            get("header-center"),
            get("header-right"),
        ],
        footer: [get("footer-left"), get("footer-center")],
    };
    let lines = source
        .lines()
        .filter(|line| !line.starts_with("%%"))
        .map(|line| line.trim_end().to_owned())
        .collect();
    (settings, lines)
}

/// Lines starting in column 0, after the document header at the top.
fn find_headings(lines: &[String]) -> Vec<Heading> {
    let header_end = lines.iter().position(|line| line.is_empty()).unwrap_or(0);
    lines[header_end..]
        .iter()
        .filter(|line| !line.is_empty() && !line.starts_with(' ') && *line != "{{toc}}")
        .map(|line| {
            let number = line.split_once("  ").map_or("", |(number, _)| number);
            let (anchor, toc_level) = if let Some(letter) = number
                .strip_prefix("Appendix ")
                .and_then(|rest| rest.strip_suffix('.'))
            {
                (format!("appendix-{letter}"), Some(1))
            } else if !number.is_empty() && number.chars().all(|c| c.is_ascii_digit() || c == '.') {
                let number = number.trim_end_matches('.');
                (
                    format!("section-{number}"),
                    Some(number.matches('.').count() + 1),
                )
            } else {
                let slug = line
                    .to_ascii_lowercase()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
                    .collect::<String>()
                    .replace(' ', "-");
                let listed = matches!(line.as_str(), "Acknowledgements" | "Author's Address");
                (format!("section-{slug}"), listed.then_some(1))
            };
            Heading {
                text: line.clone(),
                anchor,
                toc_level,
            }
        })
        .collect()
}

/// Groups the lines into blocks separated by blank lines, and expands `{{toc}}`.
fn blocks(lines: &[String], headings: &[Heading], pages: &[usize]) -> Vec<Block> {
    let header_end = lines.iter().position(|line| line.is_empty()).unwrap_or(0);
    let mut blocks = Vec::new();
    let mut current = Vec::new();
    let mut blank = 0;
    let mut heading_index = 0;
    for (index, text) in lines.iter().enumerate() {
        if text.is_empty() {
            if !current.is_empty() {
                blocks.push(Block {
                    lines: std::mem::take(&mut current),
                    blank_before: blank,
                });
                blank = 0;
            }
            blank += 1;
            continue;
        }
        if text == "{{toc}}" {
            current.extend(toc(headings, pages));
            continue;
        }
        let is_heading = index >= header_end && !text.starts_with(' ');
        if is_heading {
            // A heading is a block of its own, so it can be kept with what follows.
            if !current.is_empty() {
                blocks.push(Block {
                    lines: std::mem::take(&mut current),
                    blank_before: blank,
                });
                blank = 0;
            }
            blocks.push(Block {
                lines: vec![Line {
                    text: text.clone(),
                    kind: Kind::Heading,
                }],
                blank_before: blank,
            });
            blank = 0;
            heading_index += 1;
            continue;
        }
        current.push(Line {
            text: text.clone(),
            kind: Kind::Text,
        });
    }
    if !current.is_empty() {
        blocks.push(Block {
            lines: current,
            blank_before: blank,
        });
    }
    debug_assert_eq!(heading_index, headings.len());
    blocks
}

fn toc(headings: &[Heading], pages: &[usize]) -> Vec<Line> {
    headings
        .iter()
        .enumerate()
        .filter_map(|(index, heading)| {
            let level = heading.toc_level?;
            let mut text = format!("{}{}", " ".repeat(1 + 2 * level), heading.text);
            text.push(' ');
            // Dot leaders on odd columns, so the dots line up and end three spaces before
            // the page number.
            while text.len() < WIDTH - 4 {
                text.push(if text.len() % 2 == 1 { '.' } else { ' ' });
            }
            write!(text, "{:>width$}", pages[index], width = WIDTH - text.len()).unwrap();
            Some(Line {
                text,
                kind: Kind::Toc(index),
            })
        })
        .collect()
}

/// Lays the blocks out on pages, returning the body lines of each page.
fn layout(blocks: &[Block]) -> Vec<Vec<Line>> {
    let mut pages: Vec<Vec<Line>> = vec![Vec::new()];
    let capacity = |pages: &Vec<Vec<Line>>| {
        if pages.len() == 1 {
            FIRST_PAGE_BODY
        } else {
            PAGE_BODY
        }
    };
    for (index, block) in blocks.iter().enumerate() {
        let mut lines = &block.lines[..];
        loop {
            let page = pages.last().unwrap();
            let blank = if page.is_empty() {
                0
            } else {
                block.blank_before
            };
            let room = capacity(&pages).saturating_sub(page.len() + blank);
            let fits = if block.is_heading() {
                // Keep a heading with at least two lines of what follows it.
                let next = blocks
                    .get(index + 1)
                    .map_or(0, |next| next.blank_before + next.lines.len().min(2));
                lines.len() + next <= room
            } else {
                lines.len() <= room
            };
            if fits {
                let page = pages.last_mut().unwrap();
                page.extend(std::iter::repeat_n(blank_line(), blank));
                page.extend(lines.iter().cloned());
                break;
            }
            let empty_page = page.is_empty();
            let splittable = !block.is_heading()
                && lines.len() > KEEP_TOGETHER
                && (!block.is_figure() || lines.len() > capacity(&pages));
            // Leave at least two lines on each side of a page break. On an empty page
            // the block does not fit at all, so it fills the page.
            let take = if empty_page {
                room.min(lines.len())
            } else {
                room.min(lines.len().saturating_sub(2))
            };
            if empty_page || splittable && take >= 2 {
                let page = pages.last_mut().unwrap();
                page.extend(std::iter::repeat_n(blank_line(), blank));
                page.extend(lines[..take].iter().cloned());
                lines = &lines[take..];
            }
            if lines.is_empty() {
                break;
            }
            pages.push(Vec::new());
        }
    }
    pages
}

fn blank_line() -> Line {
    Line {
        text: String::new(),
        kind: Kind::Text,
    }
}

/// The page number of each heading.
fn heading_pages(pages: &[Vec<Line>], headings: &[Heading]) -> Vec<usize> {
    let mut found = Vec::with_capacity(headings.len());
    for (number, page) in pages.iter().enumerate() {
        for line in page {
            if line.kind == Kind::Heading {
                found.push(number + 1);
            }
        }
    }
    found
}

/// Adds the running header, padding and footer to each page.
fn decorate(pages: Vec<Vec<Line>>, settings: &Settings) -> Vec<Vec<Line>> {
    let count = pages.len();
    pages
        .into_iter()
        .enumerate()
        .map(|(index, body)| {
            let first = index == 0;
            let mut page = Vec::with_capacity(PAGE_LINES);
            if !first {
                page.push(Line {
                    text: three_columns(
                        &settings.header[0],
                        &settings.header[1],
                        &settings.header[2],
                    ),
                    kind: Kind::Header,
                });
                page.extend([blank_line(), blank_line()]);
            }
            let size = if first { FIRST_PAGE_BODY } else { PAGE_BODY };
            let filled = body.len();
            page.extend(body);
            page.extend(std::iter::repeat_n(blank_line(), size - filled + 2));
            page.push(Line {
                text: three_columns(
                    &settings.footer[0],
                    &settings.footer[1],
                    &format!("[Page {}]", index + 1),
                ),
                kind: Kind::Footer,
            });
            debug_assert_eq!(page.len(), PAGE_LINES, "page {} of {count}", index + 1);
            page
        })
        .collect()
}

fn three_columns(left: &str, center: &str, right: &str) -> String {
    let start = (WIDTH - center.len()) / 2;
    let mut line = format!("{left:<start$}{center}");
    let pad = WIDTH.saturating_sub(line.len() + right.len());
    line.push_str(&" ".repeat(pad));
    line.push_str(right);
    line
}

/// The labels of the reference entries, such as `RFC2119`.
fn references(lines: &[String]) -> HashSet<String> {
    lines
        .iter()
        .filter_map(|line| reference_label(line))
        .map(str::to_owned)
        .collect()
}

/// The label of a reference entry: `   [RFC2119]  Bradner, S., ...`, or the label alone
/// on its line when it is long. A citation at the start of a line is not an entry.
fn reference_label(line: &str) -> Option<&str> {
    let (label, rest) = line.strip_prefix("   [")?.split_once(']')?;
    (rest.is_empty() || rest.starts_with("  ")).then_some(label)
}

fn render_html(pages: &[Vec<Line>], headings: &[Heading], refs: &HashSet<String>) -> String {
    let anchors = headings
        .iter()
        .map(|heading| heading.anchor.clone())
        .collect::<HashSet<_>>();
    let mut heading_index = 0;
    let mut html = String::new();
    for (number, page) in pages.iter().enumerate() {
        html.push_str("<pre class=\"spec-page\">");
        for line in page {
            match line.kind {
                Kind::Header => {
                    write!(html, "<span class=\"spec-running\">{}</span>", escape(&line.text))
                }
                Kind::Footer => write!(
                    html,
                    "<span class=\"spec-running\" id=\"page-{}\">{}</span>",
                    number + 1,
                    escape(&line.text)
                ),
                Kind::Heading => {
                    let heading = &headings[heading_index];
                    heading_index += 1;
                    // A numbered heading links its number; others link their title.
                    let (link, rest) = match heading.text.split_once("  ") {
                        Some((number, title)) if heading.toc_level.is_some() => {
                            (number, format!("  {}", escape(title)))
                        }
                        _ => (heading.text.as_str(), String::new()),
                    };
                    write!(
                        html,
                        "<span class=\"spec-heading\" id=\"{0}\"><a href=\"#{0}\">{1}</a>{rest}</span>",
                        heading.anchor,
                        escape(link)
                    )
                }
                Kind::Toc(index) => {
                    let heading = &headings[index];
                    let start = line.text.find(&heading.text).unwrap_or(0);
                    let end = start + heading.text.len();
                    write!(
                        html,
                        "{}<a href=\"#{}\">{}</a>{}",
                        escape(&line.text[..start]),
                        heading.anchor,
                        escape(&line.text[start..end]),
                        escape(&line.text[end..])
                    )
                }
                Kind::Text => {
                    html.push_str(&linkify(&line.text, &anchors, refs));
                    Ok(())
                }
            }
            .unwrap();
            html.push('\n');
        }
        // The last newline would show as an empty line at the end of the page.
        html.pop();
        html.push_str("</pre>\n");
    }
    html
}

/// Escapes a line and links its section references, citations and `<https://...>` URLs.
fn linkify(line: &str, anchors: &HashSet<String>, refs: &HashSet<String>) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < line.len() {
        let rest = &line[index..];
        if let Some(url) = rest
            .strip_prefix("<https://")
            .and_then(|r| r.split_once('>'))
        {
            let url = format!("https://{}", url.0);
            write!(out, "&lt;<a href=\"{0}\">{0}</a>&gt;", escape(&url)).unwrap();
            index += url.len() + 2;
            continue;
        }
        if let Some((label, _)) = rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
            if refs.contains(label) {
                write!(out, "[<a href=\"#ref-{0}\">{0}</a>]", escape(label)).unwrap();
                index += label.len() + 2;
                continue;
            }
        }
        if let Some((length, anchor)) = section_reference(rest, anchors) {
            write!(out, "<a href=\"#{anchor}\">{}</a>", escape(&rest[..length])).unwrap();
            index += length;
            continue;
        }
        let character = rest.chars().next().unwrap();
        out.push_str(&escape(&character.to_string()));
        index += character.len_utf8();
    }
    // A reference entry is the target of its citations.
    if let Some(label) = reference_label(line) {
        if refs.contains(label) {
            return out.replacen(
                &format!("[<a href=\"#ref-{0}\">{0}</a>]", escape(label)),
                &format!("<span id=\"ref-{0}\">[{0}]</span>", escape(label)),
                1,
            );
        }
    }
    out
}

/// "Section 4.2" or "Appendix A" at the start of `text`, when this document has that
/// section. "Section 7.2 of [RFC9110]" refers to another document and is not linked.
fn section_reference(text: &str, anchors: &HashSet<String>) -> Option<(usize, String)> {
    let (prefix, kind) = if text.starts_with("Sections ") {
        ("Sections ", "section")
    } else if text.starts_with("Section ") {
        ("Section ", "section")
    } else if text.starts_with("Appendix ") {
        ("Appendix ", "appendix")
    } else {
        return None;
    };
    let rest = &text[prefix.len()..];
    let id = rest
        .char_indices()
        .take_while(|(_, c)| {
            if kind == "appendix" {
                c.is_ascii_uppercase()
            } else {
                c.is_ascii_digit() || *c == '.'
            }
        })
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    let number = rest[..id].trim_end_matches('.');
    if number.is_empty() || rest[number.len()..].starts_with(" of [") {
        return None;
    }
    let anchor = format!("{kind}-{number}");
    anchors
        .contains(&anchor)
        .then(|| (prefix.len() + number.len(), anchor))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{find_headings, read_source, references, SOURCE, SPEC, WIDTH};

    fn pages() -> Vec<&'static str> {
        SPEC.text().split("\n\u{c}\n").collect()
    }

    #[test]
    fn pages_have_58_lines_of_at_most_72_characters() {
        for (index, page) in pages().into_iter().enumerate() {
            let lines = page.trim_end_matches('\n').split('\n').collect::<Vec<_>>();
            assert_eq!(lines.len(), 58, "page {}", index + 1);
            for line in lines {
                assert!(line.len() <= WIDTH, "page {}: {line}", index + 1);
            }
        }
    }

    #[test]
    fn pages_have_running_headers_and_numbered_footers() {
        let pages = pages();
        assert!(pages[0].starts_with("AFWD Specification "));
        for (index, page) in pages.iter().enumerate() {
            let lines = page.trim_end_matches('\n').split('\n').collect::<Vec<_>>();
            if index > 0 {
                assert!(lines[0].starts_with("afwd-spec-01"), "page {}", index + 1);
                assert!(lines[0].ends_with("November 2026"));
            }
            let footer = lines.last().unwrap();
            assert!(footer.starts_with("Kroesbergen"));
            assert!(footer.ends_with(&format!("[Page {}]", index + 1)));
        }
    }

    #[test]
    fn table_of_contents_gives_the_page_of_each_section() {
        let pages = pages();
        let toc = pages
            .iter()
            .flat_map(|page| page.lines())
            .skip_while(|line| *line != "Table of Contents")
            .take_while(|line| *line != "1.  Introduction")
            .filter(|line| line.contains(" . "))
            .collect::<Vec<_>>();
        assert!(toc.len() > 30, "{toc:?}");
        for entry in toc {
            let (title, page) = entry.trim().rsplit_once(' ').unwrap();
            let title = title.trim_end_matches([' ', '.']);
            let page: usize = page.parse().unwrap();
            let lines = pages[page - 1].lines().collect::<Vec<_>>();
            assert!(lines.contains(&title), "{title} is not on page {page}");
        }
    }

    #[test]
    fn no_page_ends_with_a_heading() {
        for page in pages() {
            let body = page
                .lines()
                .rev()
                .skip(1)
                .find(|line| !line.is_empty())
                .unwrap();
            assert!(body.starts_with(' ') || body.is_empty(), "{body}");
        }
    }

    #[test]
    fn section_references_and_citations_resolve() {
        let (_, lines) = read_source(SOURCE);
        let anchors = find_headings(&lines)
            .into_iter()
            .map(|heading| heading.anchor)
            .collect::<HashSet<_>>();
        let refs = references(&lines);
        let text = lines.join(" ");
        let words = text.split_whitespace().collect::<Vec<_>>();
        let mut cited = HashSet::new();
        for (index, word) in words.iter().enumerate() {
            if matches!(*word, "Section" | "(Section" | "Sections") {
                let number = words[index + 1].trim_end_matches([',', '.', ')', ';', ':']);
                let external = words.get(index + 2) == Some(&"of");
                if !external && number.starts_with(|c: char| c.is_ascii_digit()) {
                    assert!(
                        anchors.contains(&format!("section-{number}")),
                        "Section {number}"
                    );
                }
            }
            if let Some(label) = word
                .trim_start_matches('(')
                .strip_prefix('[')
                .and_then(|w| w.split_once(']'))
                .map(|w| w.0)
            {
                if label.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                    assert!(refs.contains(label), "[{label}] is not in the references");
                    cited.insert(label.to_owned());
                }
            }
        }
        // Each entry names itself, so look for citations outside the references.
        let start = lines.iter().position(|l| l == "12.  References").unwrap();
        let end = lines
            .iter()
            .position(|l| l.starts_with("Appendix A."))
            .unwrap();
        let outside = [&lines[..start], &lines[end..]].concat().join(" ");
        for label in &refs {
            assert!(
                outside.contains(&format!("[{label}]")),
                "[{label}] is never cited"
            );
        }
    }

    #[test]
    fn html_links_sections_references_and_urls() {
        let html = SPEC.html();
        assert!(html.contains("id=\"section-4.2\""));
        assert!(html.contains("<a href=\"#section-4.2\">Section 4.2</a>"));
        assert!(html.contains("<span id=\"ref-RFC2119\">[RFC2119]</span>"));
        assert!(html.contains("[<a href=\"#ref-RFC2119\">RFC2119</a>]"));
        assert!(html.contains("<a href=\"https://afwd.nl/spec\">https://afwd.nl/spec</a>"));
        assert!(html.contains("id=\"appendix-A\""));
        // Sections of other documents are not linked to this one.
        assert!(html.contains("(Section 7.2 of [<a href=\"#ref-RFC9110\">RFC9110</a>])"));
        assert!(!html.contains("<script"));
        assert!(html.contains("&lt;host&gt;") || html.contains("_afwd.&lt;name&gt;"));
    }
}
