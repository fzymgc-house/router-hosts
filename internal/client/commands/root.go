package commands

import (
	"fmt"
	"os"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/samber/oops"
	"github.com/spf13/cobra"
)

// GlobalFlags holds CLI flags shared across all subcommands.
type GlobalFlags struct {
	Server  string
	Cert    string
	Key     string
	CA      string
	Config  string
	Format  string
	Quiet   bool
	Verbose bool
}

// Flags is the singleton global flags instance populated by Cobra.
var Flags GlobalFlags

// NewRootCmd creates the top-level CLI command with all subcommand groups.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "router-hosts",
		Short: "Manage DNS host entries via gRPC",
		Long:  "router-hosts is a CLI for managing /etc/hosts entries through a gRPC server with mTLS authentication.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global persistent flags
	pf := root.PersistentFlags()
	pf.StringVar(&Flags.Server, "server", "", "gRPC server address (host:port)")
	pf.StringVar(&Flags.Cert, "cert", "", "path to client TLS certificate")
	pf.StringVar(&Flags.Key, "key", "", "path to client TLS private key")
	pf.StringVar(&Flags.CA, "ca", "", "path to CA certificate for server verification")
	pf.StringVar(&Flags.Config, "config", "", "path to config file (default: auto-detected)")
	pf.StringVarP(&Flags.Format, "format", "f", "", "output format: table, json, csv (default: table for TTY, json for pipes)")
	pf.BoolVarP(&Flags.Quiet, "quiet", "q", false, "suppress non-essential output")
	pf.BoolVarP(&Flags.Verbose, "verbose", "v", false, "enable verbose output")

	// Subcommand groups
	root.AddCommand(newHostCmd())
	root.AddCommand(newSnapshotCmd())
	root.AddCommand(newServerCmd())
	root.AddCommand(newServeCmd())

	return root
}

// Execute runs the root command and exits with an appropriate code.
func Execute() {
	root := NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newHostCmd creates the "host" subcommand group.
func newHostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "host",
		Aliases: []string{"h"},
		Short:   "Manage host entries",
	}
	addHostSubcommands(cmd)
	addImportExportSubcommands(cmd)
	return cmd
}

// newSnapshotCmd creates the "snapshot" subcommand group.
func newSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "snapshot",
		Aliases: []string{"snap", "s"},
		Short:   "Manage database snapshots",
	}
	addSnapshotSubcommands(cmd)
	return cmd
}

// newServerCmd creates the "server" subcommand group for health/status.
func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server health and status commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Check server health",
		RunE:  runServerHealth,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "liveness",
		Short: "Check server liveness",
		RunE:  runServerLiveness,
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "readiness",
		Short: "Check server readiness",
		RunE:  runServerReadiness,
	})

	return cmd
}

func runServerHealth(cmd *cobra.Command, _ []string) error {
	c, err := newClientFromFlags()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := commandContext()
	defer cancel()

	resp, err := c.Hosts.Health(ctx, &hostsv1.HealthRequest{})
	if err != nil {
		return oops.Wrapf(err, "checking health")
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Healthy: %v\n", resp.GetHealthy())
	if s := resp.GetServer(); s != nil {
		fmt.Fprintf(w, "Version: %s  Uptime: %ds\n", s.GetVersion(), s.GetUptimeSeconds())
	}
	if db := resp.GetDatabase(); db != nil {
		fmt.Fprintf(w, "Database: %s connected=%v latency=%dms\n", db.GetBackend(), db.GetConnected(), db.GetLatencyMs())
	}
	if a := resp.GetAcme(); a != nil {
		fmt.Fprintf(w, "ACME: enabled=%v status=%s\n", a.GetEnabled(), a.GetStatus())
	}
	if h := resp.GetHooks(); h != nil {
		fmt.Fprintf(w, "Hooks: %d configured\n", h.GetConfiguredCount())
	}
	return nil
}

func runServerLiveness(cmd *cobra.Command, _ []string) error {
	c, err := newClientFromFlags()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := commandContext()
	defer cancel()

	resp, err := c.Hosts.Liveness(ctx, &hostsv1.LivenessRequest{})
	if err != nil {
		return oops.Wrapf(err, "checking liveness")
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Alive: %v\n", resp.GetAlive())
	return nil
}

func runServerReadiness(cmd *cobra.Command, _ []string) error {
	c, err := newClientFromFlags()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := commandContext()
	defer cancel()

	resp, err := c.Hosts.Readiness(ctx, &hostsv1.ReadinessRequest{})
	if err != nil {
		return oops.Wrapf(err, "checking readiness")
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Ready: %v\n", resp.GetReady())
	if resp.GetReason() != "" {
		fmt.Fprintf(w, "Reason: %s\n", resp.GetReason())
	}
	return nil
}
