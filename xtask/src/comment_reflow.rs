//! Conservative Rust line-comment reflow support for the repository formatter.
//!
//! The formatter is intentionally narrower than rustfmt's comment handling. It only rewrites
//! contiguous full-line comment blocks that look like plain prose, and it skips comments whose
//! layout may carry meaning in Markdown, code examples, or hand-aligned text.
//!
//! The CLI includes regular `//` comments by default. Callers can still use [`Config`] to restrict
//! reflowing to rustdoc comments (`///` and `//!`) when they need a narrower pass.

use std::ffi::OsStr;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tree_sitter::{Node, Parser};

/// Comment reflow settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Target total line width, including indentation and comment marker.
    pub width: usize,

    /// Whether regular `//` comments should be reflowed in addition to rustdoc comments.
    pub include_normal_comments: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Prefix {
    InnerDoc,
    OuterDoc,
    Normal,
}

impl Prefix {
    fn parse(comment: &str, include_normal_comments: bool) -> Option<(Self, &str)> {
        if let Some(rest) = comment.strip_prefix("//!") {
            return Some((Self::InnerDoc, rest));
        }

        // Four-slash comments are usually deliberate non-rustdoc comments and should not be
        // normalized into `///`-style prose.
        if comment.starts_with("////") {
            return None;
        }

        if let Some(rest) = comment.strip_prefix("///") {
            return Some((Self::OuterDoc, rest));
        }

        if include_normal_comments {
            return comment.strip_prefix("//").map(|rest| (Self::Normal, rest));
        }

        None
    }

    const fn marker(self) -> &'static str {
        match self {
            Self::InnerDoc => "//!",
            Self::OuterDoc => "///",
            Self::Normal => "//",
        }
    }
}

/// A full-line comment with enough source position data to replace its original line.
#[derive(Debug, Eq, PartialEq)]
struct CommentLine {
    line_idx: usize,
    line_start: usize,
    line_end: usize,
    indent: String,
    prefix: Prefix,
    content: String,
}

/// A byte-range rewrite to be applied to the original source.
#[derive(Debug, Eq, PartialEq)]
struct Replacement {
    range: Range<usize>,
    text: String,
}

/// Reflow all safe comment blocks in a Rust source string.
///
/// The source is parsed with tree-sitter so that only syntactic line comments are considered. This
/// avoids touching comment-looking text inside strings, macros, or other token contexts where regex
/// matching would be unsafe.
pub fn reflow_source(source: &str, config: Config) -> Result<String> {
    let mut parser = Parser::new();
    let language = tree_sitter::Language::from(tree_sitter_rust::LANGUAGE);
    parser.set_language(&language).context("loading tree-sitter Rust grammar")?;

    let tree = parser.parse(source, None).context("tree-sitter returned no parse tree")?;
    let line_starts = line_starts(source);
    let comment_lines =
        comment_lines(source, tree.root_node(), &line_starts, config.include_normal_comments);
    let replacements = replacements(&comment_lines, config.width);

    Ok(apply_replacements(source, &replacements))
}

/// Collect Rust source files from explicit files, directories, or the repository root.
///
/// Directory traversal skips common generated or dependency directories so the default repository
/// run stays scoped to checked-in source.
pub fn rust_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if paths.is_empty() {
        collect_rust_files(Path::new("."), &mut files)?;
    } else {
        for path in paths {
            collect_rust_files(path, &mut files)
                .with_context(|| format!("walking {}", path.display()))?;
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata =
        fs_err::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;

    if metadata.is_file() {
        if path.extension() == Some(OsStr::new("rs")) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !metadata.is_dir() || should_skip_dir(path) {
        return Ok(());
    }

    for entry in fs_err::read_dir(path)? {
        collect_rust_files(&entry?.path(), files)?;
    }

    Ok(())
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| matches!(name, ".git" | "target" | "node_modules"))
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];

    for (idx, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(idx + 1);
        }
    }

    starts
}

fn comment_lines(
    source: &str,
    root: Node<'_>,
    line_starts: &[usize],
    include_normal_comments: bool,
) -> Vec<CommentLine> {
    let mut ranges = Vec::new();
    collect_line_comment_ranges(root, &mut ranges);
    ranges.sort_by_key(|range| range.start);

    ranges
        .into_iter()
        .filter_map(|range| comment_line(source, range, line_starts, include_normal_comments))
        .collect()
}

fn collect_line_comment_ranges(node: Node<'_>, ranges: &mut Vec<Range<usize>>) {
    if node.kind() == "line_comment" {
        ranges.push(node.byte_range());
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_line_comment_ranges(child, ranges);
    }
}

fn comment_line(
    source: &str,
    range: Range<usize>,
    line_starts: &[usize],
    include_normal_comments: bool,
) -> Option<CommentLine> {
    let line_idx = line_starts.partition_point(|start| *start <= range.start) - 1;
    let line_start = *line_starts.get(line_idx)?;
    let line_end = line_end(source, line_idx, line_starts);

    // Reflow only full-line comments. Trailing comments are often attached to nearby code and can
    // be semantically or stylistically different from prose blocks.
    if !source[line_start..range.start].chars().all(char::is_whitespace) {
        return None;
    }

    let comment = &source[range.start..range.end.min(line_end)];
    let (prefix, content) = Prefix::parse(comment, include_normal_comments)?;

    Some(CommentLine {
        line_idx,
        line_start,
        line_end,
        indent: source[line_start..range.start].to_owned(),
        prefix,
        content: content.to_owned(),
    })
}

fn line_end(source: &str, line_idx: usize, line_starts: &[usize]) -> usize {
    let line_start = line_starts[line_idx];
    let next_line_start = line_starts.get(line_idx + 1).copied().unwrap_or(source.len());
    let mut end = next_line_start;

    if end > line_start && source.as_bytes()[end - 1] == b'\n' {
        end -= 1;
    }

    if end > line_start && source.as_bytes()[end - 1] == b'\r' {
        end -= 1;
    }

    end
}

fn replacements(comment_lines: &[CommentLine], width: usize) -> Vec<Replacement> {
    let mut replacements = Vec::new();
    let mut block_start = 0;

    while block_start < comment_lines.len() {
        let mut block_end = block_start + 1;

        // Only adjacent lines with the same indentation and marker are joined into one paragraph.
        // Blank lines, indentation changes, and prefix changes are treated as paragraph boundaries.
        while block_end < comment_lines.len()
            && same_block(&comment_lines[block_end - 1], &comment_lines[block_end])
        {
            block_end += 1;
        }

        if let Some(replacement) = reflow_block(&comment_lines[block_start..block_end], width) {
            replacements.push(replacement);
        }

        block_start = block_end;
    }

    replacements
}

fn same_block(previous: &CommentLine, current: &CommentLine) -> bool {
    previous.line_idx + 1 == current.line_idx
        && previous.indent == current.indent
        && previous.prefix == current.prefix
}

fn reflow_block(block: &[CommentLine], width: usize) -> Option<Replacement> {
    let first = block.first()?;
    let last = block.last()?;
    let line_prefix = format!("{}{}", first.indent, first.prefix.marker());
    let text_width = width.checked_sub(line_prefix.chars().count() + 1)?;

    if text_width == 0 {
        return None;
    }

    let mut words = Vec::new();
    for line in block {
        let text = safe_comment_text(&line.content)?;
        for word in text.split_whitespace() {
            // Do not split long words or URLs. If one word cannot fit, leave the block untouched.
            if word.chars().count() > text_width {
                return None;
            }
            words.push(word);
        }
    }

    if words.is_empty() {
        return None;
    }

    let text = wrap_words(&line_prefix, &words, text_width);
    let range = first.line_start..last.line_end;

    Some(Replacement { range, text })
}

fn safe_comment_text(content: &str) -> Option<&str> {
    let text = content.strip_prefix(' ').unwrap_or(content).trim_end();

    if text.starts_with(char::is_whitespace) || has_intentional_spacing(text) {
        return None;
    }

    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() != text.len() {
        return None;
    }

    if is_markdown_sensitive(trimmed) {
        return None;
    }

    Some(trimmed)
}

fn has_intentional_spacing(text: &str) -> bool {
    // Multiple spaces and tabs often mean alignment, ASCII diagrams, or manually spaced examples.
    text.contains('\t') || text.as_bytes().windows(2).any(|window| window == b"  ")
}

fn is_markdown_sensitive(trimmed: &str) -> bool {
    // Markdown structures can change meaning when lines are merged or rewrapped.
    trimmed.starts_with("```")
        || trimmed.starts_with("~~~")
        || trimmed.starts_with('#')
        || trimmed.starts_with('>')
        || is_list_item(trimmed)
        || is_table_row(trimmed)
        || is_url_only(trimmed)
        || is_link_reference(trimmed)
}

fn is_list_item(trimmed: &str) -> bool {
    if trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ") {
        return true;
    }

    let marker_len = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    marker_len > 0
        && trimmed[marker_len..]
            .strip_prefix(['.', ')'])
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn is_table_row(trimmed: &str) -> bool {
    trimmed.starts_with('|') || trimmed.ends_with('|') || trimmed.contains(" | ")
}

fn is_url_only(trimmed: &str) -> bool {
    let without_brackets = trimmed
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(trimmed);

    (without_brackets.starts_with("http://") || without_brackets.starts_with("https://"))
        && !without_brackets.chars().any(char::is_whitespace)
}

fn is_link_reference(trimmed: &str) -> bool {
    trimmed.starts_with('[') && trimmed.contains("]:")
}

fn wrap_words(line_prefix: &str, words: &[&str], text_width: usize) -> String {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in words {
        let word_len = word.chars().count();
        let current_len = current.chars().count();

        if current.is_empty() {
            current.push_str(word);
        } else if current_len + 1 + word_len <= text_width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(format!("{line_prefix} {current}"));
            current.clear();
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(format!("{line_prefix} {current}"));
    }

    lines.join("\n")
}

fn apply_replacements(source: &str, replacements: &[Replacement]) -> String {
    if replacements.is_empty() {
        return source.to_owned();
    }

    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;

    for replacement in replacements {
        output.push_str(&source[cursor..replacement.range.start]);
        output.push_str(&replacement.text);
        cursor = replacement.range.end;
    }

    output.push_str(&source[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::{Config, reflow_source};

    fn reflow(source: &str, width: usize) -> String {
        reflow_source(source, Config { width, include_normal_comments: false }).unwrap()
    }

    #[test]
    fn reflows_outer_doc_comment_blocks() {
        let source = r"/// This is a doc comment that should be wrapped into a few short lines by
/// the formatter.
fn main() {}
";

        let expected = r"/// This is a doc comment that
/// should be wrapped into a
/// few short lines by the
/// formatter.
fn main() {}
";

        assert_eq!(reflow(source, 30), expected);
    }

    #[test]
    fn does_not_reflow_trailing_comments() {
        let source = r"fn main() {
    let _value = 1; /// this trailing doc comment is ignored by design
}
";

        assert_eq!(reflow(source, 40), source);
    }

    #[test]
    fn skips_markdown_lists() {
        let source = r"/// - first item that should stay exactly where it is
/// - second item that should stay exactly where it is
fn main() {}
";

        assert_eq!(reflow(source, 30), source);
    }

    #[test]
    fn can_reflow_regular_comments_when_enabled() {
        let source = r"// A normal comment can also be wrapped when the caller explicitly asks for all comments.
fn main() {}
";

        let reflowed =
            reflow_source(source, Config { width: 45, include_normal_comments: true }).unwrap();

        assert_eq!(
            reflowed,
            r"// A normal comment can also be wrapped when
// the caller explicitly asks for all
// comments.
fn main() {}
"
        );
    }
}
