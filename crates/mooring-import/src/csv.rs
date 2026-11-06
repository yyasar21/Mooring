//! A small RFC 4180 reader for the Termius CSV export (owner decision: no `csv` crate).
//! Fields may be quoted (`""` escapes a quote; quoted fields may hold newlines and commas);
//! records end at `\n` or `\r\n`. Caps: field length ≤ `max_text`, columns per record ≤
//! [`MAX_COLUMNS`]. Malformed quoting is `import.format` with the record number.

use crate::error::{ImportError, Result};
use crate::limits::Limits;

/// Most columns a record may have.
pub const MAX_COLUMNS: usize = 64;

/// Parsed records, each a list of fields (the first record is the header).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {
    /// Records in order.
    pub records: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    FieldStart,
    Unquoted,
    Quoted,
    QuoteInQuoted,
}

fn err(what: &'static str, record: usize) -> ImportError {
    ImportError::format("termius_csv", what, record as u64)
}

/// Parse `text` into records. Empty lines are skipped. The final record needs no newline.
pub fn parse(text: &str, limits: &Limits) -> Result<Table> {
    let mut table = Table::default();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut state = State::FieldStart;
    let mut chars = text.chars().peekable();
    let push_field = |record: &mut Vec<String>, field: &mut String| -> Result<()> {
        if record.len() >= MAX_COLUMNS {
            return Err(ImportError::limits("csv columns"));
        }
        record.push(std::mem::take(field));
        Ok(())
    };
    let end_record = |table: &mut Table, record: &mut Vec<String>| {
        let rec = std::mem::take(record);
        if !(rec.len() == 1 && rec[0].is_empty()) {
            table.records.push(rec);
        }
    };
    while let Some(c) = chars.next() {
        let n = table.records.len() + 1;
        match (state, c) {
            (State::FieldStart, '"') => state = State::Quoted,
            (State::FieldStart | State::Unquoted, ',') => {
                push_field(&mut record, &mut field)?;
                state = State::FieldStart;
            }
            (State::FieldStart | State::Unquoted, '\n') => {
                push_field(&mut record, &mut field)?;
                end_record(&mut table, &mut record);
                state = State::FieldStart;
            }
            (State::FieldStart | State::Unquoted, '\r') if chars.peek() == Some(&'\n') => {}
            (State::FieldStart | State::Unquoted, '\r') => return Err(err("bare CR", n)),
            (State::Unquoted, '"') => return Err(err("quote inside field", n)),
            (State::FieldStart | State::Unquoted, c) => {
                field.push(c);
                state = State::Unquoted;
            }
            (State::Quoted, '"') => state = State::QuoteInQuoted,
            (State::Quoted, c) => field.push(c),
            (State::QuoteInQuoted, '"') => {
                field.push('"');
                state = State::Quoted;
            }
            (State::QuoteInQuoted, ',') => {
                push_field(&mut record, &mut field)?;
                state = State::FieldStart;
            }
            (State::QuoteInQuoted, '\n') => {
                push_field(&mut record, &mut field)?;
                end_record(&mut table, &mut record);
                state = State::FieldStart;
            }
            (State::QuoteInQuoted, '\r') if chars.peek() == Some(&'\n') => {}
            (State::QuoteInQuoted, _) => return Err(err("text after closing quote", n)),
        }
        if field.len() > limits.max_text {
            return Err(ImportError::limits("csv field length"));
        }
    }
    match state {
        State::Quoted => return Err(err("unterminated quote", table.records.len() + 1)),
        State::FieldStart if record.is_empty() => {}
        _ => {
            push_field(&mut record, &mut field)?;
            end_record(&mut table, &mut record);
        }
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(t: &str) -> Vec<Vec<String>> {
        parse(t, &Limits::DEFAULT).expect("parse").records
    }

    #[test]
    fn rfc_4180_shapes() {
        assert_eq!(rows("a,b\n1,2\n"), vec![vec!["a", "b"], vec!["1", "2"]]);
        assert_eq!(rows("a,b\r\n1,2"), vec![vec!["a", "b"], vec!["1", "2"]]);
        assert_eq!(rows("\"x,y\",\"he said \"\"hi\"\"\"\n"), vec![vec!["x,y", "he said \"hi\""]]);
        assert_eq!(rows("\"multi\nline\",z\n"), vec![vec!["multi\nline", "z"]]);
        assert_eq!(rows("a,,c\n\n,\n"), vec![vec!["a", "", "c"], vec!["", ""]]);
        assert_eq!(rows(""), Vec::<Vec<String>>::new());
        assert_eq!(rows("\"\"\n"), Vec::<Vec<String>>::new());
    }

    #[test]
    fn malformed_quoting_names_the_record() {
        for (t, what) in [
            ("a,\"b\n", "unterminated quote"),
            ("a,b\"c\n", "quote inside field"),
            ("\"a\"b,c\n", "text after closing quote"),
            ("a\rb\n", "bare CR"),
        ] {
            let e = parse(t, &Limits::DEFAULT).expect_err(t);
            assert_eq!(e, ImportError::format("termius_csv", what, 1), "{t}");
        }
    }

    #[test]
    fn caps() {
        let mut l = Limits::DEFAULT;
        l.max_text = 3;
        assert_eq!(parse("abcd\n", &l), Err(ImportError::limits("csv field length")));
        assert_eq!(parse("\"abcd\"\n", &l), Err(ImportError::limits("csv field length")));
        let wide = ",".repeat(MAX_COLUMNS);
        assert_eq!(parse(&wide, &Limits::DEFAULT), Err(ImportError::limits("csv columns")));
    }
}
