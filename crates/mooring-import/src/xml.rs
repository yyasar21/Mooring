//! Guarded XML reading on `quick-xml` (ADR-0019 §3): any `<!DOCTYPE` is refused (no DTD,
//! no custom entities, no `XInclude`), only the five predefined and numeric character
//! references resolve, and depth, element count and text / attribute length are capped
//! before anything is stored. The result is a small owned tree of local names.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use quick_xml::XmlVersion;

use crate::error::{ImportError, Result};
use crate::limits::Limits;

/// One element: local name (prefix dropped), attributes, concatenated text, children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    /// Local element name.
    pub name: String,
    /// `(local name, unescaped value)`.
    pub attrs: Vec<(String, String)>,
    /// Direct text content (whitespace-only chunks dropped), trimmed.
    pub text: String,
    /// Child elements in order.
    pub children: Vec<Node>,
}

impl Node {
    /// An attribute by local name (first match).
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The first child by local name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Children by local name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Trimmed text of the first child by name, `None` when absent or blank.
    #[must_use]
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str()).filter(|t| !t.is_empty())
    }

    /// Text at a child path, `None` when any step is missing or the text blank.
    #[must_use]
    pub fn path_text(&self, path: &[&str]) -> Option<&str> {
        let mut n = self;
        for p in path {
            n = n.child(p)?;
        }
        Some(n.text.as_str()).filter(|t| !t.is_empty())
    }

    /// The first non-blank text among the children named in `names` (format variants).
    #[must_use]
    pub fn first_text(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| self.child_text(n))
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn start(e: &BytesStart<'_>, limits: &Limits, format: &'static str, at: u64) -> Result<Node> {
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|_| ImportError::format(format, "malformed attribute", at))?;
        if a.value.len() > limits.max_text {
            return Err(ImportError::limits("attribute length"));
        }
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| ImportError::format(format, "unknown entity", at))?;
        attrs.push((local(a.key.into_inner()).to_owned(), value.into_owned()));
    }
    Ok(Node { name: local(e.name().into_inner()).to_owned(), attrs, ..Node::default() })
}

fn push_text(node: &mut Node, chunk: &str, limits: &Limits) -> Result<()> {
    if node.text.len() + chunk.len() > limits.max_text {
        return Err(ImportError::limits("text length"));
    }
    node.text.push_str(chunk);
    Ok(())
}

/// Parse a whole document into its root element.
pub fn parse(text: &str, limits: &Limits, format: &'static str) -> Result<Node> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().trim_text_start = false;
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut elements = 0usize;
    loop {
        let at = reader.buffer_position();
        let event =
            reader.read_event().map_err(|_| ImportError::format(format, "malformed XML", at))?;
        match event {
            Event::DocType(_) => return Err(ImportError::Doctype { at }),
            Event::Start(e) => {
                if root.is_some() {
                    return Err(ImportError::format(format, "content after the root", at));
                }
                elements += 1;
                if elements > limits.max_xml_elements {
                    return Err(ImportError::limits("element count"));
                }
                if stack.len() >= limits.max_xml_depth {
                    return Err(ImportError::limits("nesting depth"));
                }
                stack.push(start(&e, limits, format, at)?);
            }
            Event::End(_) => {
                let Some(mut done) = stack.pop() else {
                    return Err(ImportError::format(format, "unmatched end tag", at));
                };
                let trimmed = done.text.trim().len();
                let start = done.text.len() - done.text.trim_start().len();
                done.text.truncate(start + trimmed);
                done.text.drain(..start);
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => root = Some(done),
                }
            }
            Event::Text(t) => {
                if let Some(node) = stack.last_mut() {
                    // Indentation between children is dropped; whitespace inside a text run
                    // (between two references) is kept.
                    let inside_run = !node.text.is_empty() && node.children.is_empty();
                    if inside_run || !t.trim().is_empty() {
                        push_text(node, &t, limits)?;
                    }
                }
            }
            Event::CData(c) => {
                if let Some(node) = stack.last_mut() {
                    push_text(node, &c, limits)?;
                }
            }
            Event::GeneralRef(r) => {
                let ch = match &*r {
                    "lt" => '<',
                    "gt" => '>',
                    "amp" => '&',
                    "apos" => '\'',
                    "quot" => '"',
                    _ => r
                        .resolve_char_ref()
                        .ok()
                        .flatten()
                        .ok_or_else(|| ImportError::format(format, "unknown entity", at))?,
                };
                if let Some(node) = stack.last_mut() {
                    push_text(node, ch.encode_utf8(&mut [0; 4]), limits)?;
                }
            }
            Event::Empty(_) => return Err(ImportError::format(format, "unexpected event", at)),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(ImportError::format(format, "unclosed element", reader.buffer_position()));
    }
    root.ok_or_else(|| ImportError::format(format, "no root element", 0))
}

#[cfg(test)]
#[path = "xml_tests.rs"]
mod tests;
