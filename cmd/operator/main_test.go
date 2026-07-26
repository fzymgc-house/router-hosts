package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDefaultIngressIPWarning_NamesOnlyRegisteredControllers is the WR-01
// regression: the empty --default-ingress-ip warning fires unconditionally,
// before the --enable-gateway check that decides whether the Gateway API
// controllers are ever registered. Naming them in the warning when
// enableGateway is false is misleading — an operator running only the
// IngressRoute controller with no Gateway CRDs installed would see a
// warning referencing a feature they never enabled.
func TestDefaultIngressIPWarning_NamesOnlyRegisteredControllers(t *testing.T) {
	assert.Equal(
		t,
		"--default-ingress-ip is empty; IngressRoute controller will create hosts with no IP",
		defaultIngressIPWarning(false),
	)
	assert.Equal(
		t,
		"--default-ingress-ip is empty; IngressRoute and Gateway API controllers will create hosts with no IP",
		defaultIngressIPWarning(true),
	)
}
