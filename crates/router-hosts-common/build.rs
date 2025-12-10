fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Download pre-built protoc binary (much faster than compiling from source)
    // dlprotoc::download_protoc() sets PROTOC env var automatically
    dlprotoc::download_protoc()?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Only derive serde for specific types we need to serialize
        .type_attribute("router_hosts.v1.HostEntry", "#[derive(serde::Serialize)]")
        .type_attribute("router_hosts.v1.Snapshot", "#[derive(serde::Serialize)]")
        .type_attribute(
            "router_hosts.v1.CreateSnapshotResponse",
            "#[derive(serde::Serialize)]",
        )
        .type_attribute(
            "router_hosts.v1.RollbackToSnapshotResponse",
            "#[derive(serde::Serialize)]",
        )
        .type_attribute(
            "router_hosts.v1.DeleteSnapshotResponse",
            "#[derive(serde::Serialize)]",
        )
        // Skip timestamp fields when serializing
        .field_attribute("router_hosts.v1.HostEntry.created_at", "#[serde(skip)]")
        .field_attribute("router_hosts.v1.HostEntry.updated_at", "#[serde(skip)]")
        .field_attribute("router_hosts.v1.Snapshot.created_at", "#[serde(skip)]")
        .compile_protos(
            &["../../proto/router_hosts/v1/hosts.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
