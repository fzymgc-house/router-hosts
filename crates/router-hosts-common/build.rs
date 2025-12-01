fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Download pre-built protoc binary (much faster than compiling from source)
    // dlprotoc::download_protoc() sets PROTOC env var automatically
    dlprotoc::download_protoc()?;

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../../proto/router_hosts/v1/hosts.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
