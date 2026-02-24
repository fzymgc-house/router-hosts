package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSearchFilter_Validate(t *testing.T) {
	tests := []struct {
		name    string
		filter  SearchFilter
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid filter all fields set",
			filter: SearchFilter{
				IPPattern:       ptr("10.*"),
				HostnamePattern: ptr("db.*"),
				Tags:            []string{"prod"},
				Query:           ptr("database"),
			},
			wantErr: false,
		},
		{
			name:    "nil fields (zero value) is valid",
			filter:  SearchFilter{},
			wantErr: false,
		},
		{
			name:    "empty IPPattern returns error",
			filter:  SearchFilter{IPPattern: ptr("")},
			wantErr: true,
			errMsg:  "ip_pattern must not be an empty string",
		},
		{
			name:    "empty HostnamePattern returns error",
			filter:  SearchFilter{HostnamePattern: ptr("")},
			wantErr: true,
			errMsg:  "hostname_pattern must not be an empty string",
		},
		{
			name:    "empty Query returns error",
			filter:  SearchFilter{Query: ptr("")},
			wantErr: true,
			errMsg:  "query must not be an empty string",
		},
		{
			name: "all pattern fields empty returns error on first check",
			filter: SearchFilter{
				IPPattern:       ptr(""),
				HostnamePattern: ptr(""),
				Query:           ptr(""),
			},
			wantErr: true,
			errMsg:  "ip_pattern must not be an empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSearchFilter_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		filter SearchFilter
		want   bool
	}{
		{
			name:   "zero value",
			filter: SearchFilter{},
			want:   true,
		},
		{
			name:   "ip pattern set",
			filter: SearchFilter{IPPattern: ptr("192.168.*")},
			want:   false,
		},
		{
			name:   "hostname pattern set",
			filter: SearchFilter{HostnamePattern: ptr("*.local")},
			want:   false,
		},
		{
			name:   "tags set",
			filter: SearchFilter{Tags: []string{"prod"}},
			want:   false,
		},
		{
			name:   "query set",
			filter: SearchFilter{Query: ptr("server")},
			want:   false,
		},
		{
			name:   "empty tags slice",
			filter: SearchFilter{Tags: []string{}},
			want:   true,
		},
		{
			name: "all fields set",
			filter: SearchFilter{
				IPPattern:       ptr("10.*"),
				HostnamePattern: ptr("db.*"),
				Tags:            []string{"prod"},
				Query:           ptr("database"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.filter.IsEmpty())
		})
	}
}
