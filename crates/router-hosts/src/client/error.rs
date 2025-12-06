use tonic::{Code, Status};

/// Exit codes following Unix conventions
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Convert gRPC status to user-friendly error message
pub fn format_grpc_error(status: &Status) -> String {
    match status.code() {
        Code::InvalidArgument => format!("Invalid input: {}", status.message()),
        Code::NotFound => format!("Not found: {}", status.message()),
        Code::AlreadyExists => format!("Already exists: {}", status.message()),
        Code::Aborted => "Version conflict: entry was modified. Re-fetch and try again.".to_string(),
        Code::PermissionDenied => "Permission denied: check TLS certificates".to_string(),
        Code::Unavailable => "Server unavailable: check address and connectivity".to_string(),
        Code::Unauthenticated => "Authentication failed: check TLS certificates".to_string(),
        _ => format!("Server error: {}", status.message()),
    }
}

/// Get exit code for gRPC status
pub fn exit_code_for_status(status: &Status) -> i32 {
    match status.code() {
        Code::InvalidArgument => EXIT_USAGE,
        Code::Aborted => EXIT_CONFLICT,
        _ => EXIT_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_invalid_argument() {
        let status = Status::invalid_argument("hostname too long");
        assert_eq!(format_grpc_error(&status), "Invalid input: hostname too long");
    }

    #[test]
    fn test_format_not_found() {
        let status = Status::not_found("entry 01J... not found");
        assert_eq!(format_grpc_error(&status), "Not found: entry 01J... not found");
    }

    #[test]
    fn test_format_aborted() {
        let status = Status::aborted("version mismatch");
        let msg = format_grpc_error(&status);
        assert!(msg.contains("Version conflict"));
    }

    #[test]
    fn test_exit_code_invalid_argument() {
        let status = Status::invalid_argument("bad");
        assert_eq!(exit_code_for_status(&status), EXIT_USAGE);
    }

    #[test]
    fn test_exit_code_aborted() {
        let status = Status::aborted("conflict");
        assert_eq!(exit_code_for_status(&status), EXIT_CONFLICT);
    }

    #[test]
    fn test_exit_code_general_error() {
        let status = Status::internal("unexpected");
        assert_eq!(exit_code_for_status(&status), EXIT_ERROR);
    }
}
