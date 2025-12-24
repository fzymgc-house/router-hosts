//! DuckDB variant of router-hosts.
//!
//! This binary provides the same functionality as `router-hosts` but includes
//! the DuckDB storage backend in addition to SQLite and PostgreSQL.
//!
//! Use this variant if you need DuckDB's analytics capabilities or are
//! migrating from an existing DuckDB-based installation.

use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    router_hosts::run().await
}
