use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    router_hosts::run().await
}
