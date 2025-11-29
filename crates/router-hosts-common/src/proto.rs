// Re-export generated protobuf code
pub mod router_hosts {
    pub mod v1 {
        tonic::include_proto!("router_hosts.v1");
    }
    pub use v1::*;
}

pub use router_hosts::*;
