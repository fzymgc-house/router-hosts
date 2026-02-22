package domain

import (
	"errors"
	"testing"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestGRPCCode(t *testing.T) {
	tests := []struct {
		code     string
		expected codes.Code
	}{
		{CodeVersionConflict, codes.Aborted},
		{CodeNotFound, codes.NotFound},
		{CodeDuplicate, codes.AlreadyExists},
		{CodeValidation, codes.InvalidArgument},
		{CodeInternal, codes.Internal},
		{CodeStorage, codes.Internal},
		{"unknown_code", codes.Unknown},
		{"", codes.Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			assert.Equal(t, tt.expected, GRPCCode(tt.code))
		})
	}
}

func TestErrNotFound(t *testing.T) {
	err := ErrNotFound("host", "abc-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `host "abc-123" not found`)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeNotFound, code)
}

func TestErrDuplicate(t *testing.T) {
	err := ErrDuplicate("192.168.1.1", "server.local")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate entry: 192.168.1.1 -> server.local")

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeDuplicate, code)
}

func TestErrVersionConflict(t *testing.T) {
	err := ErrVersionConflict("agg-1", "v2", "v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version conflict on agg-1: expected v2, got v1")

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeVersionConflict, code)
}

func TestErrValidation(t *testing.T) {
	err := ErrValidation("hostname is empty")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed: hostname is empty")

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeValidation, code)
}

func TestErrValidationf(t *testing.T) {
	err := ErrValidationf("field %q must be at least %d chars", "hostname", 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `validation failed: field "hostname" must be at least 3 chars`)

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeValidation, code)
}

func TestErrInternal(t *testing.T) {
	cause := errors.New("disk full")
	err := ErrInternal(cause)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeInternal, code)
}

func TestErrStorage(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrStorage(cause)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")

	oopsErr, ok := oops.AsOops(err)
	require.True(t, ok)
	code, _ := oopsErr.Code().(string)
	assert.Equal(t, CodeStorage, code)
}
