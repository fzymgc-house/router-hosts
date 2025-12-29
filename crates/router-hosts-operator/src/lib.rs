//! router-hosts-operator: Kubernetes controller for DNS host synchronization

pub mod client;
pub mod config;
pub mod controllers;
pub mod deletion;
pub mod hostmapping;
pub mod matcher;
pub mod resolver;

pub use config::RouterHostsConfig;
pub use hostmapping::HostMapping;
