use tonic::{Code, Status};

/// Exit codes following Unix conventions
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Convert gRPC status to user-friendly error message
pub fn format_grpc_error(status: &Status) -> String {
    match status.code() {
        Code::InvalidArgument => format!("Invalid input: {}", status.message()),
        Code::NotFound => format!("Not found: {}", status.message()),
        Code::AlreadyExists => format!("Already exists: {}", status.message()),
        Code::Aborted => {
            "Version conflict: entry was modified. Re-fetch and try again.".to_string()
        }
        Code::PermissionDenied => "Permission denied: check TLS certificates".to_string(),
        Code::Unavailable => "Server unavailable: check address and connectivity".to_string(),
        Code::Unauthenticated => "Authentication failed: check TLS certificates".to_string(),
        Code::Cancelled => {
            // TLS handshake failures often appear as "cancelled" operations
            // when the server rejects the client certificate
            "TLS certificate rejected: server refused connection".to_string()
        }
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
        assert_eq!(
            format_grpc_error(&status),
            "Invalid input: hostname too long"
        );
    }

    #[test]
    fn test_format_not_found() {
        let status = Status::not_found("entry 01J... not found");
        assert_eq!(
            format_grpc_error(&status),
            "Not found: entry 01J... not found"
        );
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

    #[test]
    fn test_format_already_exists() {
        let status = Status::already_exists("hostname test.local already exists");
        assert_eq!(
            format_grpc_error(&status),
            "Already exists: hostname test.local already exists"
        );
    }

    #[test]
    fn test_format_permission_denied() {
        let status = Status::permission_denied("access denied");
        assert!(format_grpc_error(&status).contains("Permission denied"));
    }

    #[test]
    fn test_format_unavailable() {
        let status = Status::unavailable("server down");
        assert!(format_grpc_error(&status).contains("unavailable"));
    }

    #[test]
    fn test_format_unauthenticated() {
        let status = Status::unauthenticated("bad cert");
        assert!(format_grpc_error(&status).contains("Authentication failed"));
    }

    #[test]
    fn test_format_internal_error() {
        let status = Status::internal("database error");
        assert_eq!(format_grpc_error(&status), "Server error: database error");
    }

    #[test]
    fn test_exit_code_not_found() {
        let status = Status::not_found("missing");
        assert_eq!(exit_code_for_status(&status), EXIT_ERROR);
    }

    #[test]
    fn test_format_cancelled_tls() {
        let status = Status::cancelled("connection cancelled");
        let msg = format_grpc_error(&status);
        assert!(msg.contains("TLS") || msg.contains("certificate"));
    }
}
