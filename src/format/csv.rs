use std::fmt;

use crate::core::{Printer, Sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvError(String);

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CsvError {}

#[cfg(test)]
pub(crate) fn format_csv(buf: &[u8], color: bool) -> Result<Vec<u8>, CsvError> {
    let mut out = Printer::new(color);
    format_csv_to_with_terminal_cols(buf, &mut out, 0)?;
    Ok(out.into_bytes())
}

#[cfg(test)]
pub(crate) fn format_csv_with_terminal_cols(
    buf: &[u8],
    color: bool,
    terminal_columns: usize,
) -> Result<String, CsvError> {
    let mut out = Printer::new(color);
    format_csv_to_with_terminal_cols(buf, &mut out, terminal_columns)?;
    out.into_string()
        .map_err(|err| CsvError(format!("invalid UTF-8 output: {err}")))
}

pub fn format_csv_to(buf: &[u8], out: &mut Printer) -> Result<(), CsvError> {
    format_csv_to_with_terminal_cols(buf, out, 0)
}

pub(crate) fn format_csv_to_with_terminal_cols(
    buf: &[u8],
    out: &mut Printer,
    terminal_columns: usize,
) -> Result<(), CsvError> {
    if buf.is_empty() {
        return Ok(());
    }

    let delimiter = detect_delimiter(buf);
    let records = parse_records(&String::from_utf8_lossy(buf), delimiter);
    if records.is_empty() {
        return Ok(());
    }

    let column_widths = calculate_column_widths(&records);
    let total_width = calculate_total_width(&column_widths);
    if terminal_columns > 0 && total_width > terminal_columns && records.len() > 1 {
        write_vertical_to(out, &records);
        return Ok(());
    }

    for (index, row) in records.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        write_row(out, row, &column_widths, index == 0);
    }
    out.push('\n');
    Ok(())
}

fn parse_records(input: &str, delimiter: char) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut start_field = true;
    let mut ended_record = false;

    while let Some(ch) = chars.next() {
        ended_record = false;
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
            start_field = false;
            continue;
        }

        if ch == '"' && start_field {
            in_quotes = true;
            start_field = false;
            continue;
        }

        if ch == delimiter {
            row.push(std::mem::take(&mut field));
            start_field = true;
            continue;
        }

        if ch == '\n' || ch == '\r' {
            if ch == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            row.push(std::mem::take(&mut field));
            records.push(std::mem::take(&mut row));
            start_field = true;
            ended_record = true;
            continue;
        }

        field.push(ch);
        start_field = false;
    }

    if !ended_record || !row.is_empty() || !field.is_empty() {
        row.push(field);
        records.push(row);
    }

    records
}

fn detect_delimiter(buf: &[u8]) -> char {
    let first_line = buf.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let first_line = String::from_utf8_lossy(first_line);
    let delimiters = [',', '\t', ';', '|'];

    let mut max_count = 0;
    let mut best_delimiter = ',';
    for delimiter in delimiters {
        let count = first_line.matches(delimiter).count();
        if count > max_count {
            max_count = count;
            best_delimiter = delimiter;
        }
    }

    best_delimiter
}

fn calculate_column_widths(records: &[Vec<String>]) -> Vec<usize> {
    let max_columns = records.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; max_columns];
    for row in records {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(display_width(cell));
        }
    }
    widths
}

fn calculate_total_width(column_widths: &[usize]) -> usize {
    let total = column_widths.iter().sum::<usize>();
    if column_widths.len() > 1 {
        total + (column_widths.len() - 1) * 2
    } else {
        total
    }
}

fn write_row(out: &mut Printer, row: &[String], column_widths: &[usize], is_header: bool) {
    for (index, cell) in row.iter().enumerate() {
        if index > 0 {
            out.push_str("  ");
        }

        if is_header {
            out.write_styled(cell, &[Sequence::Blue, Sequence::Bold]);
        } else {
            out.write_styled(cell, &[Sequence::Green]);
        }

        if index < column_widths.len() - 1 {
            let padding = column_widths[index].saturating_sub(display_width(cell));
            for _ in 0..padding {
                out.push(' ');
            }
        }
    }
}

fn write_vertical_to(out: &mut Printer, records: &[Vec<String>]) {
    let headers = records.first().map(Vec::as_slice).unwrap_or(&[]);
    let max_header_width = headers
        .iter()
        .map(|header| display_width(header))
        .max()
        .unwrap_or(0);

    for (row_index, row) in records.iter().skip(1).enumerate() {
        if row_index > 0 {
            out.push('\n');
        }

        out.write_styled(
            &format!("--- Row {} ---\n", row_index + 1),
            &[Sequence::Dim],
        );

        for (column_index, cell) in row.iter().enumerate() {
            let header = headers.get(column_index).map(String::as_str).unwrap_or("");
            let padding = max_header_width.saturating_sub(display_width(header));
            for _ in 0..padding {
                out.push(' ');
            }
            out.write_styled(header, &[Sequence::Blue, Sequence::Bold]);
            out.push_str(": ");
            out.write_styled(cell, &[Sequence::Green]);
            out.push('\n');
        }
    }
}

#[cfg(test)]
fn write_vertical(records: &[Vec<String>], color: bool) -> String {
    let mut out = Printer::new(color);
    write_vertical_to(&mut out, records);
    out.into_string()
        .expect("CSV formatter output is valid UTF-8")
}

fn display_width(value: &str) -> usize {
    value
        .chars()
        .map(|ch| {
            if ch == '\n' || ch == '\r' {
                0
            } else if is_wide(ch) {
                2
            } else {
                1
            }
        })
        .sum()
}

fn is_wide(ch: char) -> bool {
    matches!(
        ch as u32,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1f64f
            | 0x1f900..=0x1f9ff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_csv() {
        let tests = [
            ("basic csv", "name,age,city\nAlice,30,NYC\nBob,25,LA"),
            (
                "tab separated",
                "name\tage\tcity\nAlice\t30\tNYC\nBob\t25\tLA",
            ),
            (
                "semicolon separated",
                "name;age;city\nAlice;30;NYC\nBob;25;LA",
            ),
            ("pipe separated", "name|age|city\nAlice|30|NYC\nBob|25|LA"),
            (
                "quoted fields with commas",
                "name,location,notes\nAlice,\"New York, NY\",\"Has a cat, dog\"\nBob,LA,None",
            ),
            (
                "embedded newlines in quotes",
                "name,bio\nAlice,\"Line1\nLine2\"\nBob,Simple",
            ),
            ("empty input", ""),
            ("ragged rows", "a,b,c\n1,2\n3,4,5,6"),
            ("single column", "name\nAlice\nBob"),
            ("single row", "name,age,city"),
            ("unicode content", "名前,年齢\n太郎,25\n花子,30"),
        ];

        for (name, input) in tests {
            format_csv(input.as_bytes(), false).unwrap_or_else(|err| panic!("{name}: {err}"));
        }
    }

    #[test]
    fn test_format_csv_output() {
        let output = String::from_utf8(
            format_csv(b"name,age,city\nAlice,30,NYC\nBob,25,LA", false).unwrap(),
        )
        .unwrap();

        for want in [
            "name", "age", "city", "Alice", "30", "NYC", "Bob", "25", "LA",
        ] {
            assert!(
                output.contains(want),
                "output should contain {want:?}: {output}"
            );
        }
        assert!(output.matches('\n').count() >= 3, "{output}");
    }

    #[test]
    fn test_format_csv_alignment() {
        let output = String::from_utf8(format_csv(b"a,bb,ccc\n111,22,3", false).unwrap()).unwrap();
        let lines = output.trim_end_matches('\n').lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("a  "), "{:?}", lines[0]);
    }

    #[test]
    fn test_detect_delimiter() {
        let tests = [
            ("comma", "a,b,c", ','),
            ("tab", "a\tb\tc", '\t'),
            ("semicolon", "a;b;c", ';'),
            ("pipe", "a|b|c", '|'),
            ("empty defaults to comma", "", ','),
            ("no delimiters defaults to comma", "abc", ','),
            ("mixed prefers most common", "a,b,c;d", ','),
            ("multiline uses first line", "a;b;c\na,b,c,d,e", ';'),
        ];

        for (name, input, want) in tests {
            assert_eq!(detect_delimiter(input.as_bytes()), want, "{name}");
        }
    }

    #[test]
    fn test_format_csv_empty() {
        assert_eq!(format_csv(b"", false).unwrap(), b"");
    }

    #[test]
    fn test_calculate_total_width() {
        let tests = [
            ("single column", vec![10], 10),
            ("two columns", vec![10, 20], 32),
            ("three columns", vec![5, 10, 15], 34),
            ("empty", vec![], 0),
        ];

        for (name, widths, want) in tests {
            assert_eq!(calculate_total_width(&widths), want, "{name}");
        }
    }

    #[test]
    fn test_vertical_output() {
        let records = vec![
            vec!["name".into(), "age".into(), "city".into()],
            vec!["Alice".into(), "30".into(), "NYC".into()],
            vec!["Bob".into(), "25".into(), "LA".into()],
        ];
        let output = write_vertical(&records, false);

        for want in [
            "--- Row 1 ---",
            "--- Row 2 ---",
            "name:",
            "age:",
            "city:",
            "Alice",
            "30",
            "NYC",
            "Bob",
            "25",
            "LA",
        ] {
            assert!(
                output.contains(want),
                "output should contain {want:?}: {output}"
            );
        }
    }

    #[test]
    fn test_vertical_output_header_alignment() {
        let records = vec![
            vec!["a".into(), "longer_header".into()],
            vec!["val1".into(), "val2".into()],
        ];
        let output = write_vertical(&records, false);

        let line = output.lines().find(|line| line.contains("a:")).unwrap();
        assert!(line.starts_with("            a:"), "{line:?}");
    }

    #[test]
    fn test_unicode_display_width() {
        let tests = [
            ("ascii", vec![vec!["hello".into()], vec!["world".into()]], 5),
            ("cjk", vec![vec!["名前".into()], vec!["ab".into()]], 4),
            (
                "mixed",
                vec![vec!["hello世界".into()], vec!["test".into()]],
                9,
            ),
        ];

        for (name, records, want) in tests {
            let widths = calculate_column_widths(&records);
            assert_eq!(widths[0], want, "{name}");
        }
    }

    #[test]
    fn test_vertical_mode_with_ragged_rows() {
        let records = vec![
            vec!["a".into(), "b".into(), "c".into()],
            vec!["1".into(), "2".into()],
            vec!["x".into(), "y".into(), "z".into()],
        ];
        let output = write_vertical(&records, false);

        assert!(output.contains("--- Row 1 ---"));
        assert!(output.contains("--- Row 2 ---"));
        assert!(output.contains("x") && output.contains("y") && output.contains("z"));
    }

    #[test]
    fn test_vertical_mode_with_extra_columns() {
        let records = vec![
            vec!["a".into(), "b".into()],
            vec!["1".into(), "2".into(), "3".into()],
        ];
        let output = write_vertical(&records, false);

        assert!(output.contains("3"), "{output}");
    }

    #[test]
    fn formats_csv_with_color_when_requested() {
        let output = String::from_utf8(format_csv(b"name,age\nAlice,30", true).unwrap()).unwrap();

        assert!(output.contains("\x1b[34m\x1b[1mname\x1b[0m"));
        assert!(output.contains("\x1b[32mAlice\x1b[0m"));
    }

    #[test]
    fn vertical_mode_uses_terminal_width_boundary() {
        let output =
            format_csv_with_terminal_cols(b"name,age,city\nAlice,30,NYC", false, 5).unwrap();

        assert!(output.contains("--- Row 1 ---"), "{output}");
    }
}
