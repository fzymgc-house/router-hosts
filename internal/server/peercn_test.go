package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// testLeafCert builds a minimal *x509.Certificate carrying only the subject
// common name needed to exercise commonNameFromContext. It is never signed
// or parsed from DER — only its in-memory Subject field is read.
func testLeafCert(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func TestCommonNameFromContext(t *testing.T) {
	t.Parallel()

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}

	tests := []struct {
		name     string
		buildCtx func() context.Context
		wantCN   string
		wantErr  bool
	}{
		{
			name: "verified chain returns leaf common name",
			buildCtx: func() context.Context {
				p := &peer.Peer{
					Addr: addr,
					AuthInfo: credentials.TLSInfo{
						State: tls.ConnectionState{
							VerifiedChains: [][]*x509.Certificate{
								{testLeafCert("sink-1")},
							},
						},
					},
				}
				return peer.NewContext(context.Background(), p)
			},
			wantCN:  "sink-1",
			wantErr: false,
		},
		{
			name:     "no peer info in context",
			buildCtx: context.Background,
			wantCN:   "",
			wantErr:  true,
		},
		{
			name: "peer auth info is not TLS",
			buildCtx: func() context.Context {
				p := &peer.Peer{Addr: addr, AuthInfo: insecureAuthInfoStub{}}
				return peer.NewContext(context.Background(), p)
			},
			wantCN:  "",
			wantErr: true,
		},
		{
			name: "empty verified chain list",
			buildCtx: func() context.Context {
				p := &peer.Peer{
					Addr: addr,
					AuthInfo: credentials.TLSInfo{
						State: tls.ConnectionState{
							VerifiedChains: [][]*x509.Certificate{},
						},
					},
				}
				return peer.NewContext(context.Background(), p)
			},
			wantCN:  "",
			wantErr: true,
		},
		{
			name: "first verified chain is empty",
			buildCtx: func() context.Context {
				p := &peer.Peer{
					Addr: addr,
					AuthInfo: credentials.TLSInfo{
						State: tls.ConnectionState{
							VerifiedChains: [][]*x509.Certificate{{}},
						},
					},
				}
				return peer.NewContext(context.Background(), p)
			},
			wantCN:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cn, err := commonNameFromContext(tt.buildCtx())
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, cn)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCN, cn)
		})
	}
}

// insecureAuthInfoStub implements credentials.AuthInfo without being
// credentials.TLSInfo, exercising the type-assertion failure path.
type insecureAuthInfoStub struct{}

func (insecureAuthInfoStub) AuthType() string { return "insecure" }
