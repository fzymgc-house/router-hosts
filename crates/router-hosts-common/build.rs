fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use bundled protoc to avoid requiring system installation
    std::env::set_var("PROTOC", protobuf_src::protoc());

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../../proto/router_hosts/v1/hosts.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
