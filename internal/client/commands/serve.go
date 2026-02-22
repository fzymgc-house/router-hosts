package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/server"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// defaultHookTimeout is the maximum duration for a single hook execution.
const defaultHookTimeout = 30 * time.Second

func newServeCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC server",
		Long:  "Start the router-hosts gRPC server with mTLS, loading configuration from a TOML file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to server TOML config file (required)")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func runServe(ctx context.Context, configPath string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load config
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Initialize SQLite storage
	dbPath, err := cfg.Database.ResolveDBPath()
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}

	store, err := sqlite.New(dbPath, logger)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			logger.Error("store close failed", "error", cerr)
		}
	}()

	if err := store.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}

	// Create command handler
	handler := server.NewCommandHandler(store)

	// Build service options
	var svcOpts []server.ServiceOption

	// Hosts file generator (optional)
	var hostsGen *server.HostsFileGenerator
	if cfg.Server.HostsFilePath != "" {
		hostsGen = server.NewHostsFileGenerator(cfg.Server.HostsFilePath)
		svcOpts = append(svcOpts, server.WithHostsGenerator(hostsGen))
	}

	// Hook executor (optional)
	if len(cfg.Hooks.OnSuccess) > 0 || len(cfg.Hooks.OnFailure) > 0 {
		hookExec := server.NewHookExecutor(
			cfg.Hooks.OnSuccess,
			cfg.Hooks.OnFailure,
			defaultHookTimeout,
			logger,
		)
		svcOpts = append(svcOpts, server.WithHookExecutor(hookExec))
	}

	// Create gRPC service implementation
	svc := server.NewHostsServiceImpl(handler, store, svcOpts...)

	// Set up OTel metrics (optional)
	var metrics *server.Metrics
	var serverOpts []server.Option

	if cfg.Metrics != nil && cfg.Metrics.OTel != nil {
		metrics, err = server.NewMetricsFromConfig(cfg.Metrics.OTel)
		if err != nil {
			return fmt.Errorf("setup metrics: %w", err)
		}
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if serr := metrics.Shutdown(shutCtx); serr != nil {
				logger.Error("metrics shutdown failed", "error", serr)
			}
		}()

		serverOpts = append(serverOpts, server.WithGRPCOptions(
			grpc.ChainUnaryInterceptor(server.UnaryMetricsInterceptor(metrics)),
			grpc.ChainStreamInterceptor(server.StreamMetricsInterceptor(metrics)),
		))
	}

	// Create and configure gRPC server
	srv, err := server.NewServer(*cfg, store, logger, serverOpts...)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	hostsv1.RegisterHostsServiceServer(srv.GRPCServer(), svc)

	logger.Info("server configured",
		"bind_address", cfg.Server.BindAddress,
		"database", dbPath,
		"hosts_file", cfg.Server.HostsFilePath,
	)

	return srv.Run(ctx)
}
