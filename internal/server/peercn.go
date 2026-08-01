package server

import (
	"context"

	"github.com/samber/oops"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// commonNameFromContext reads the calling consumer's verified identity from
// a gRPC stream or unary context: peer.FromContext, then a type assertion of
// the peer's AuthInfo to credentials.TLSInfo, then
// VerifiedChains[0][0].Subject.CommonName.
//
// The guards below are defensive, not load-bearing: internal/server/server.go
// sets ClientAuth: tls.RequireAndVerifyClientCert on the server's TLS config,
// so a connection cannot reach an RPC handler at all without a CA-verified
// client certificate, and VerifiedChains is therefore guaranteed non-empty
// for any request that gets this far.
//
// This is the ONLY permitted source of sink identity for a metric label
// (D-13): a caller-supplied name — anything from a request body, header, or
// status payload — would let one client mint unbounded label values or
// impersonate another consumer's health record, and it cannot be un-shipped
// once dashboards depend on it.
func commonNameFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", oops.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", oops.Errorf("connection is not TLS-authenticated")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", oops.Errorf("no verified client certificate chain")
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, nil
}
