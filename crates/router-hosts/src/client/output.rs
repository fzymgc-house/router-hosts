use router_hosts_common::proto::{HostEntry, Snapshot};
use serde::Serialize;

use super::OutputFormat;

/// Trait for types that can be displayed in table format
pub trait TableDisplay {
    fn headers() -> Vec<&'static str>;
    fn row(&self) -> Vec<String>;
}

impl TableDisplay for HostEntry {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "IP", "HOSTNAME", "COMMENT", "TAGS"]
    }

    fn row(&self) -> Vec<String> {
        let id_display = if self.id.len() > 12 {
            format!("{}...", &self.id[..12])
        } else {
            self.id.clone()
        };

        vec![
            id_display,
            self.ip_address.clone(),
            self.hostname.clone(),
            self.comment.clone().unwrap_or_default(),
            self.tags.join(","),
        ]
    }
}

impl TableDisplay for Snapshot {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "CREATED", "ENTRIES", "TRIGGER"]
    }

    fn row(&self) -> Vec<String> {
        let id_display = if self.snapshot_id.len() > 12 {
            format!("{}...", &self.snapshot_id[..12])
        } else {
            self.snapshot_id.clone()
        };

        let created = self
            .created_at
            .as_ref()
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "invalid".to_string())
            })
            .unwrap_or_default();

        vec![
            id_display,
            created,
            self.entry_count.to_string(),
            self.trigger.clone(),
        ]
    }
}

/// Print items in the specified format
pub fn print_items<T>(items: &[T], format: OutputFormat)
where
    T: TableDisplay + Serialize,
{
    match format {
        OutputFormat::Table => print_table(items),
        OutputFormat::Json => print_json(items),
        OutputFormat::Csv => print_csv(items),
    }
}

/// Print a single item
pub fn print_item<T>(item: &T, format: OutputFormat)
where
    T: TableDisplay + Serialize,
{
    print_items(std::slice::from_ref(item), format);
}

fn print_table<T: TableDisplay>(items: &[T]) {
    if items.is_empty() {
        return;
    }

    let headers = T::headers();
    let rows: Vec<Vec<String>> = items.iter().map(|i| i.row()).collect();

    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.join("  "));

    // Print rows
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let width = widths.get(i).copied().unwrap_or(0);
                format!("{:width$}", cell, width = width)
            })
            .collect();
        println!("{}", line.join("  "));
    }
}

fn print_json<T: Serialize>(items: &[T]) {
    match serde_json::to_string_pretty(items) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}

fn print_csv<T: TableDisplay>(items: &[T]) {
    let mut writer = csv::Writer::from_writer(std::io::stdout());

    // Write headers
    let headers = T::headers();
    if let Err(e) = writer.write_record(&headers) {
        eprintln!("Error writing CSV headers: {}", e);
        return;
    }

    // Write rows
    for item in items {
        let row = item.row();
        if let Err(e) = writer.write_record(&row) {
            eprintln!("Error writing CSV row: {}", e);
            return;
        }
    }

    if let Err(e) = writer.flush() {
        eprintln!("Error flushing CSV output: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_entry_row() {
        let entry = HostEntry {
            id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: Some("Test host".to_string()),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            created_at: None,
            updated_at: None,
            version: "1".to_string(),
        };

        let row = entry.row();
        assert_eq!(row[0], "01JXXXXXXXXX...");
        assert_eq!(row[1], "192.168.1.1");
        assert_eq!(row[2], "test.local");
        assert_eq!(row[3], "Test host");
        assert_eq!(row[4], "tag1,tag2");
    }

    #[test]
    fn test_host_entry_row_short_id() {
        let entry = HostEntry {
            id: "SHORT".to_string(),
            ip_address: "10.0.0.1".to_string(),
            hostname: "short.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: None,
            updated_at: None,
            version: "1".to_string(),
        };

        let row = entry.row();
        // Short ID should not be truncated
        assert_eq!(row[0], "SHORT");
        // Empty comment should be empty string
        assert_eq!(row[3], "");
        // Empty tags should be empty string
        assert_eq!(row[4], "");
    }

    #[test]
    fn test_host_entry_headers() {
        let headers = HostEntry::headers();
        assert_eq!(headers, vec!["ID", "IP", "HOSTNAME", "COMMENT", "TAGS"]);
    }

    #[test]
    fn test_snapshot_headers() {
        let headers = Snapshot::headers();
        assert_eq!(headers, vec!["ID", "CREATED", "ENTRIES", "TRIGGER"]);
    }

    #[test]
    fn test_snapshot_row() {
        let snapshot = Snapshot {
            snapshot_id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            created_at: Some(prost_types::Timestamp {
                seconds: 1733500000,
                nanos: 0,
            }),
            entry_count: 42,
            trigger: "manual".to_string(),
        };

        let row = snapshot.row();
        assert_eq!(row[0], "01JXXXXXXXXX...");
        assert!(row[1].contains("2024")); // Year should be in the timestamp
        assert_eq!(row[2], "42");
        assert_eq!(row[3], "manual");
    }

    #[test]
    fn test_snapshot_row_no_timestamp() {
        let snapshot = Snapshot {
            snapshot_id: "SHORT".to_string(),
            created_at: None,
            entry_count: 0,
            trigger: "rollback".to_string(),
        };

        let row = snapshot.row();
        assert_eq!(row[0], "SHORT");
        assert_eq!(row[1], ""); // No timestamp
        assert_eq!(row[2], "0");
        assert_eq!(row[3], "rollback");
    }

    #[test]
    fn test_csv_escaping() {
        let entry = HostEntry {
            id: "01J".to_string(),
            ip_address: "1.1.1.1".to_string(),
            hostname: "test".to_string(),
            comment: Some("Has, comma".to_string()),
            tags: vec![],
            created_at: None,
            updated_at: None,
            version: "1".to_string(),
        };

        let row = entry.row();
        // The comment should be escaped when printed
        assert!(row[3].contains(','));
    }
}
