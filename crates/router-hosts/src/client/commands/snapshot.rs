use anyhow::Result;
use router_hosts_common::proto::{
    CreateSnapshotRequest, DeleteSnapshotRequest, ListSnapshotsRequest, RollbackToSnapshotRequest,
};

use crate::client::{
    grpc::Client,
    output::{print_item, print_items},
    OutputFormat, SnapshotCommand,
};

pub async fn handle(
    client: &mut Client,
    command: SnapshotCommand,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    match command {
        SnapshotCommand::Create => {
            let request = CreateSnapshotRequest {
                name: String::new(),    // Empty = auto-generate
                trigger: String::new(), // Empty = "manual"
            };
            let response = client.create_snapshot(request).await?;
            if !quiet {
                print_item(&response, format);
            }
        }

        SnapshotCommand::List => {
            let request = ListSnapshotsRequest {
                limit: 0,  // 0 = no limit
                offset: 0, // 0 = no offset
            };
            let responses = client.list_snapshots(request).await?;
            let snapshots: Vec<_> = responses.into_iter().filter_map(|r| r.snapshot).collect();
            print_items(&snapshots, format);
        }

        SnapshotCommand::Rollback { snapshot_id } => {
            let request = RollbackToSnapshotRequest { snapshot_id };
            let response = client.rollback_to_snapshot(request).await?;
            if !quiet && response.success {
                eprintln!("Rolled back successfully");
                eprintln!("Backup snapshot created: {}", response.new_snapshot_id);
            }
        }

        SnapshotCommand::Delete { snapshot_id } => {
            let request = DeleteSnapshotRequest { snapshot_id };
            let response = client.delete_snapshot(request).await?;
            if !quiet && response.success {
                eprintln!("Deleted snapshot successfully");
            }
        }
    }
    Ok(())
}
