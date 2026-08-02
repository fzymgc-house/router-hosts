// Package server provides the gRPC server with mTLS support for router-hosts.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/samber/oops"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// GracefulShutdownTimeout is the maximum time to wait for in-flight RPCs.
const GracefulShutdownTimeout = 30 * time.Second

// KeepaliveParams returns the gRPC keepalive.ServerParameters this server
// applies to every connection. The 30s ping interval and 10s timeout replace
// grpc-go's default two-hour ping interval, which is far too coarse for the
// sink last-seen signal (D-09/D-10, T-1-13): a dead TCP connection could
// otherwise sit undetected for hours.
//
// MaxConnectionIdle, MaxConnectionAge and MaxConnectionAgeGrace are
// deliberately left at their zero values (disabled). Setting any of them
// would tear down a healthy long-lived sink stream on a timer, which is
// exactly the failure mode TMPL-08's continuous sink mode must not have
// (T-1-14).
func KeepaliveParams() keepalive.ServerParameters {
	return keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}
}

// KeepaliveEnforcementPolicy returns the minimum ping interval this server
// accepts from clients. MinTime must stay at or below the client's
// configured keepalive.ClientParameters.Time (see
// internal/client.KeepaliveParams): a client pinging more often than MinTime
// is sent GOAWAY. PermitWithoutStream is enabled so a client with no active
// RPC — a sink between snapshots — is not penalized for pinging (T-1-12).
func KeepaliveEnforcementPolicy() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}
}

// KeepaliveServerOptions bundles the keepalive gRPC ServerOptions this server
// applies. NewServer inserts these ahead of any caller-supplied
// WithGRPCOptions, so a caller can still override them explicitly.
func KeepaliveServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(KeepaliveParams()),
		grpc.KeepaliveEnforcementPolicy(KeepaliveEnforcementPolicy()),
	}
}

// Server wraps a gRPC server with mTLS and lifecycle management.
type Server struct {
	listener    net.Listener
	grpc        *grpc.Server
	cfg         config.Config
	storage     storage.Storage
	log         *slog.Logger
	grpcOptions []grpc.ServerOption

	// mTLS cert hot-reload state
	mu       sync.RWMutex
	certPath string
	keyPath  string
	cert     *tls.Certificate
}

// Option configures a Server. Used for testing (e.g. injecting a listener).
type Option func(*Server)

// WithListener sets a pre-created listener (useful for bufconn testing).
func WithListener(l net.Listener) Option {
	return func(s *Server) {
		s.listener = l
	}
}

// WithGRPCOptions appends additional gRPC server options (e.g. interceptors).
// NOTE: pass all interceptors in a single call using grpc.ChainUnaryInterceptor
// and grpc.ChainStreamInterceptor; multiple separate interceptor options result
// in only the last one being active.
func WithGRPCOptions(opts ...grpc.ServerOption) Option {
	return func(s *Server) {
		s.grpcOptions = append(s.grpcOptions, opts...)
	}
}

// NewServer creates a gRPC server configured with mTLS from the given config.
func NewServer(cfg config.Config, store storage.Storage, logger *slog.Logger, opts ...Option) (*Server, error) {
	s := &Server{
		cfg:      cfg,
		storage:  store,
		log:      logger,
		certPath: cfg.TLS.CertPath,
		keyPath:  cfg.TLS.KeyPath,
	}

	for _, o := range opts {
		o(s)
	}

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return nil, oops.Code(domain.CodeInternal).Wrapf(err, "configure TLS")
	}

	creds := credentials.NewTLS(tlsConfig)
	keepaliveOpts := KeepaliveServerOptions()
	grpcOpts := make([]grpc.ServerOption, 0, 1+len(keepaliveOpts)+len(s.grpcOptions))
	grpcOpts = append(grpcOpts, grpc.Creds(creds))
	grpcOpts = append(grpcOpts, keepaliveOpts...)
	grpcOpts = append(grpcOpts, s.grpcOptions...)
	s.grpc = grpc.NewServer(grpcOpts...)

	return s, nil
}

// RegisterService registers a gRPC service implementation on the server.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl any) {
	s.grpc.RegisterService(desc, impl)
}

// GRPCServer returns the underlying grpc.Server for direct registration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpc
}

// Run starts the gRPC server and blocks until shutdown.
// It handles SIGTERM/SIGINT for graceful shutdown and SIGHUP for cert reload.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		lis, err := net.Listen("tcp", s.cfg.Server.BindAddress)
		if err != nil {
			return oops.Code(domain.CodeInternal).Wrapf(err, "listen on %s", s.cfg.Server.BindAddress)
		}
		s.listener = lis
	}

	s.log.Info("starting gRPC server",
		"address", s.listener.Addr().String(),
		"tls", true,
	)

	// Signal handling
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.grpc.Serve(s.listener)
	}()

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				s.log.Info("received SIGHUP, reloading TLS certificates")
				if err := s.reloadCert(); err != nil {
					s.log.Error("failed to reload certificates", "error", err)
				} else {
					s.log.Info("TLS certificates reloaded successfully")
				}
			case syscall.SIGTERM, syscall.SIGINT:
				s.log.Info("received shutdown signal, draining connections",
					"signal", sig,
					"timeout", GracefulShutdownTimeout,
				)
				return s.gracefulStop()
			}
		case err := <-errCh:
			cancel()
			return err
		case <-ctx.Done():
			s.log.Info("context cancelled, shutting down")
			return s.gracefulStop()
		}
	}
}

// gracefulStop performs a graceful shutdown with a timeout.
func (s *Server) gracefulStop() error {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()

	timer := time.NewTimer(GracefulShutdownTimeout)
	defer timer.Stop()

	select {
	case <-done:
		s.log.Info("graceful shutdown complete")
		return nil
	case <-timer.C:
		s.log.Warn("graceful shutdown timed out, forcing stop")
		s.grpc.Stop()
		return nil
	}
}

// Stop immediately halts the server without draining.
func (s *Server) Stop() {
	s.grpc.Stop()
}

// buildTLSConfig creates the mTLS configuration.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	// Load server cert
	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return nil, oops.Code(domain.CodeInternal).Wrapf(err, "load server certificate")
	}
	s.mu.Lock()
	s.cert = &cert
	s.mu.Unlock()

	// Load CA for client verification
	caCert, err := os.ReadFile(s.cfg.TLS.CACertPath)
	if err != nil {
		return nil, oops.Code(domain.CodeInternal).Wrapf(err, "read CA certificate")
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, oops.Code(domain.CodeInternal).Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		GetCertificate: s.getCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// getCertificate is the TLS callback that returns the current certificate.
// This enables hot-reload via SIGHUP.
func (s *Server) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cert, nil
}

// reloadCert loads the certificate from disk and updates the in-memory cert.
func (s *Server) reloadCert() error {
	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return oops.Code(domain.CodeInternal).Wrapf(err, "reload certificate")
	}
	s.mu.Lock()
	s.cert = &cert
	s.mu.Unlock()
	return nil
}
