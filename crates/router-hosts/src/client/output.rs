use router_hosts_common::proto::{
    CreateSnapshotResponse, DeleteSnapshotResponse, HostEntry, RollbackToSnapshotResponse, Snapshot,
};
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
                    .map(|dt| format!("{} UTC", dt.format("%Y-%m-%d %H:%M")))
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

impl TableDisplay for CreateSnapshotResponse {
    fn headers() -> Vec<&'static str> {
        vec!["SNAPSHOT_ID", "CREATED_AT", "ENTRY_COUNT"]
    }

    fn row(&self) -> Vec<String> {
        let id_display = if self.snapshot_id.len() > 12 {
            format!("{}...", &self.snapshot_id[..12])
        } else {
            self.snapshot_id.clone()
        };

        // created_at is microseconds since epoch (i64)
        let created = chrono::DateTime::from_timestamp_micros(self.created_at)
            .map(|dt| format!("{} UTC", dt.format("%Y-%m-%d %H:%M")))
            .unwrap_or_else(|| "invalid".to_string());

        vec![id_display, created, self.entry_count.to_string()]
    }
}

impl TableDisplay for RollbackToSnapshotResponse {
    fn headers() -> Vec<&'static str> {
        vec!["SUCCESS", "BACKUP_SNAPSHOT_ID", "RESTORED_ENTRIES"]
    }

    fn row(&self) -> Vec<String> {
        let backup_id_display = if self.new_snapshot_id.len() > 12 {
            format!("{}...", &self.new_snapshot_id[..12])
        } else {
            self.new_snapshot_id.clone()
        };

        vec![
            self.success.to_string(),
            backup_id_display,
            self.restored_entry_count.to_string(),
        ]
    }
}

impl TableDisplay for DeleteSnapshotResponse {
    fn headers() -> Vec<&'static str> {
        vec!["SUCCESS"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.success.to_string()]
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

/// Format a single item as JSON string
fn format_item_json<T>(item: &T) -> Result<String, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_string_pretty(item)
}

/// Print a single item
pub fn print_item<T>(item: &T, format: OutputFormat)
where
    T: TableDisplay + Serialize,
{
    match format {
        OutputFormat::Json => {
            // Print single item as object (not array) for easier parsing
            match format_item_json(item) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Error serializing to JSON: {}", e),
            }
        }
        _ => {
            // For table/CSV, reuse print_items with single-element slice
            print_items(std::slice::from_ref(item), format);
        }
    }
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
            aliases: vec![],
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
            aliases: vec![],
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
            name: "test-snapshot".to_string(),
        };

        let row = snapshot.row();
        assert_eq!(row[0], "01JXXXXXXXXX...");
        assert!(row[1].contains("2024")); // Year should be in the timestamp
        assert!(row[1].ends_with(" UTC")); // Timezone indicator
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
            name: String::new(),
        };

        let row = snapshot.row();
        assert_eq!(row[0], "SHORT");
        assert_eq!(row[1], ""); // No timestamp
        assert_eq!(row[2], "0");
        assert_eq!(row[3], "rollback");
    }

    #[test]
    fn test_create_snapshot_response_headers() {
        let headers = CreateSnapshotResponse::headers();
        assert_eq!(headers, vec!["SNAPSHOT_ID", "CREATED_AT", "ENTRY_COUNT"]);
    }

    #[test]
    fn test_create_snapshot_response_row() {
        let response = CreateSnapshotResponse {
            snapshot_id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            created_at: 1733500000000000, // microseconds since epoch
            entry_count: 42,
        };

        let row = response.row();
        assert_eq!(row[0], "01JXXXXXXXXX...");
        assert!(row[1].contains("2024")); // Year should be in the timestamp
        assert!(row[1].ends_with(" UTC")); // Timezone indicator
        assert_eq!(row[2], "42");
    }

    #[test]
    fn test_create_snapshot_response_row_short_id() {
        let response = CreateSnapshotResponse {
            snapshot_id: "SHORT".to_string(),
            created_at: 0,
            entry_count: 0,
        };

        let row = response.row();
        assert_eq!(row[0], "SHORT");
        assert_eq!(row[2], "0");
    }

    #[test]
    fn test_create_snapshot_response_json_format() {
        // Verify that CreateSnapshotResponse can be serialized to JSON
        // This is critical for E2E tests that parse JSON output
        let response = CreateSnapshotResponse {
            snapshot_id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            created_at: 1733500000000000,
            entry_count: 10,
        };

        let json_str = format_item_json(&response).expect("Failed to format JSON");
        let value: serde_json::Value =
            serde_json::from_str(&json_str).expect("Failed to parse JSON output");

        // Verify it's an object with expected fields
        assert!(value.is_object(), "Should be a JSON object");
        assert_eq!(
            value.get("snapshot_id").and_then(|v| v.as_str()),
            Some("01JXXXXXXXXXXXXXXXXX")
        );
        assert_eq!(
            value.get("created_at").and_then(|v| v.as_i64()),
            Some(1733500000000000)
        );
        assert_eq!(value.get("entry_count").and_then(|v| v.as_i64()), Some(10));
    }

    #[test]
    fn test_rollback_response_headers() {
        let headers = RollbackToSnapshotResponse::headers();
        assert_eq!(
            headers,
            vec!["SUCCESS", "BACKUP_SNAPSHOT_ID", "RESTORED_ENTRIES"]
        );
    }

    #[test]
    fn test_rollback_response_row() {
        let response = RollbackToSnapshotResponse {
            success: true,
            new_snapshot_id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            restored_entry_count: 42,
        };

        let row = response.row();
        assert_eq!(row[0], "true");
        assert_eq!(row[1], "01JXXXXXXXXX...");
        assert_eq!(row[2], "42");
    }

    #[test]
    fn test_rollback_response_json_format() {
        let response = RollbackToSnapshotResponse {
            success: true,
            new_snapshot_id: "backup-snapshot-id".to_string(),
            restored_entry_count: 10,
        };

        let json_str = format_item_json(&response).expect("Failed to format JSON");
        let value: serde_json::Value =
            serde_json::from_str(&json_str).expect("Failed to parse JSON output");

        assert!(value.is_object());
        assert_eq!(value.get("success").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            value.get("new_snapshot_id").and_then(|v| v.as_str()),
            Some("backup-snapshot-id")
        );
        assert_eq!(
            value.get("restored_entry_count").and_then(|v| v.as_i64()),
            Some(10)
        );
    }

    #[test]
    fn test_delete_response_headers() {
        let headers = DeleteSnapshotResponse::headers();
        assert_eq!(headers, vec!["SUCCESS"]);
    }

    #[test]
    fn test_delete_response_row() {
        let response = DeleteSnapshotResponse { success: true };

        let row = response.row();
        assert_eq!(row[0], "true");
    }

    #[test]
    fn test_delete_response_json_format() {
        let response = DeleteSnapshotResponse { success: true };

        let json_str = format_item_json(&response).expect("Failed to format JSON");
        let value: serde_json::Value =
            serde_json::from_str(&json_str).expect("Failed to parse JSON output");

        assert!(value.is_object());
        assert_eq!(value.get("success").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn test_csv_escaping() {
        let entry = HostEntry {
            id: "01J".to_string(),
            ip_address: "1.1.1.1".to_string(),
            hostname: "test".to_string(),
            aliases: vec![],
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

    #[test]
    fn test_format_item_json_produces_object() {
        // Verify that format_item_json outputs an object structure (not array)
        // This is critical for E2E tests that need to extract the 'id' field
        let entry = HostEntry {
            id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            ip_address: "10.0.0.1".to_string(),
            hostname: "test.local".to_string(),
            aliases: vec![],
            comment: Some("Test".to_string()),
            tags: vec!["tag1".to_string()],
            created_at: None,
            updated_at: None,
            version: "v1".to_string(),
        };

        let json_str = format_item_json(&entry).expect("Failed to format JSON");
        let value: serde_json::Value =
            serde_json::from_str(&json_str).expect("Failed to parse JSON output");

        // Verify it's an object with 'id' field at top level (not wrapped in array)
        assert!(value.is_object(), "Single item should be an object");
        assert_eq!(
            value.get("id").and_then(|v| v.as_str()),
            Some("01JXXXXXXXXXXXXXXXXX")
        );
        assert_eq!(
            value.get("ip_address").and_then(|v| v.as_str()),
            Some("10.0.0.1")
        );
        assert_eq!(
            value.get("hostname").and_then(|v| v.as_str()),
            Some("test.local")
        );
    }

    #[test]
    fn test_print_item_json_no_panic() {
        // Smoke test: verify print_item with JSON format doesn't panic
        let entry = HostEntry {
            id: "test-id".to_string(),
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
            created_at: None,
            updated_at: None,
            version: "v1".to_string(),
        };

        // Should not panic
        print_item(&entry, OutputFormat::Json);
    }

    #[test]
    fn test_print_item_table_no_panic() {
        // Smoke test: verify print_item with Table format doesn't panic
        let entry = HostEntry {
            id: "test-id".to_string(),
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            aliases: vec![],
            comment: Some("Test".to_string()),
            tags: vec!["tag1".to_string()],
            created_at: None,
            updated_at: None,
            version: "v1".to_string(),
        };

        // Should not panic
        print_item(&entry, OutputFormat::Table);
    }

    #[test]
    fn test_print_item_csv_no_panic() {
        // Smoke test: verify print_item with CSV format doesn't panic
        let entry = HostEntry {
            id: "test-id".to_string(),
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
            created_at: None,
            updated_at: None,
            version: "v1".to_string(),
        };

        // Should not panic
        print_item(&entry, OutputFormat::Csv);
    }
}
