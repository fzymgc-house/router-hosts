package dockergate_test

import (
	"errors"
	"testing"

	"github.com/fzymgc-house/router-hosts/internal/testutil/dockergate"
)

func TestDecide(t *testing.T) {
	probeErr := errors.New("not found")

	tests := []struct {
		name     string
		envValue string
		probeErr error
		want     dockergate.Action
	}{
		{
			name:     "no requirement, docker present",
			envValue: "",
			probeErr: nil,
			want:     dockergate.Proceed,
		},
		{
			name:     "requirement set, docker present",
			envValue: "1",
			probeErr: nil,
			want:     dockergate.Proceed,
		},
		{
			name:     "no requirement, docker absent",
			envValue: "",
			probeErr: probeErr,
			want:     dockergate.Skip,
		},
		{
			name:     "requirement set, docker absent",
			envValue: "1",
			probeErr: probeErr,
			want:     dockergate.Fatal,
		},
		{
			name:     "presence-based not truthiness-based: 0 still means required",
			envValue: "0",
			probeErr: errors.New("x"),
			want:     dockergate.Fatal,
		},
		{
			name:     "whitespace is a non-empty value: no trimming",
			envValue: "  ",
			probeErr: errors.New("x"),
			want:     dockergate.Fatal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dockergate.Decide(tt.envValue, tt.probeErr)
			if got != tt.want {
				t.Errorf("Decide(%q, %v) = %v, want %v", tt.envValue, tt.probeErr, got, tt.want)
			}
		})
	}
}

func TestEnvVar(t *testing.T) {
	const want = "RH_E2E_REQUIRE_DOCKER"
	if dockergate.EnvVar != want {
		t.Errorf("EnvVar = %q, want %q", dockergate.EnvVar, want)
	}
}

func TestActionZeroValueIsProceed(t *testing.T) {
	var a dockergate.Action
	if a != dockergate.Proceed {
		t.Errorf("zero value of Action = %v, want Proceed (%v)", a, dockergate.Proceed)
	}
}
