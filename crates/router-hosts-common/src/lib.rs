pub mod validation;
pub mod proto;

pub use validation::{validate_hostname, validate_ip_address, ValidationError, ValidationResult};
