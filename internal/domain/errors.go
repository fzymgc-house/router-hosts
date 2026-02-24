package domain

import (
	"fmt"

	"github.com/samber/oops"
	"google.golang.org/grpc/codes"
)

// Domain error codes mapped to gRPC status codes.
const (
	CodeVersionConflict = "version_conflict"  // gRPC Aborted
	CodeNotFound        = "not_found"         // gRPC NotFound
	CodeDuplicate       = "duplicate_entry"   // gRPC AlreadyExists
	CodeValidation      = "validation_failed" // gRPC InvalidArgument
	CodeInternal        = "internal"          // gRPC Internal
	CodeStorage         = "storage_error"     // gRPC Internal
)

// GRPCCode returns the gRPC status code for a domain error code.
func GRPCCode(code string) codes.Code {
	switch code {
	case CodeVersionConflict:
		return codes.Aborted
	case CodeNotFound:
		return codes.NotFound
	case CodeDuplicate:
		return codes.AlreadyExists
	case CodeValidation:
		return codes.InvalidArgument
	case CodeInternal:
		return codes.Internal
	case CodeStorage:
		return codes.Internal
	default:
		return codes.Unknown
	}
}

// ErrNotFound returns an oops error for a missing entity.
func ErrNotFound(entity, id string) error {
	return oops.
		Code(CodeNotFound).
		With("entity", entity).
		With("id", id).
		Errorf("%s %q not found", entity, id)
}

// ErrDuplicate returns an oops error for a duplicate host entry.
func ErrDuplicate(ip, hostname string) error {
	return oops.
		Code(CodeDuplicate).
		With("ip", ip).
		With("hostname", hostname).
		Errorf("duplicate entry: %s -> %s", ip, hostname)
}

// ErrVersionConflict returns an oops error for optimistic concurrency failure.
func ErrVersionConflict(aggregateID string, expected, actual int64) error {
	return oops.
		Code(CodeVersionConflict).
		With("aggregate_id", aggregateID).
		With("expected_version", expected).
		With("actual_version", actual).
		Errorf("version conflict on %s: expected %d, got %d", aggregateID, expected, actual)
}

// ErrValidation returns an oops error for invalid input.
func ErrValidation(msg string) error {
	return oops.
		Code(CodeValidation).
		Errorf("validation failed: %s", msg)
}

// ErrValidationf returns an oops error for invalid input with format args.
func ErrValidationf(format string, args ...any) error {
	return oops.
		Code(CodeValidation).
		Errorf("validation failed: %s", fmt.Sprintf(format, args...))
}

// ErrInternal returns an oops error wrapping an internal failure.
func ErrInternal(err error) error {
	return oops.
		Code(CodeInternal).
		Wrap(err)
}

// ErrStorage returns an oops error wrapping a storage failure.
func ErrStorage(err error) error {
	return oops.
		Code(CodeStorage).
		Wrap(err)
}
