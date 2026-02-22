package commands

import (
	"fmt"
	"os"

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
	return cmd
}

// newSnapshotCmd creates the "snapshot" subcommand group.
func newSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "snapshot",
		Aliases: []string{"snap", "s"},
		Short:   "Manage database snapshots",
	}
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

// Placeholder run functions for server health commands.
// These will be wired up once the gRPC client wrapper exists.
func runServerHealth(_ *cobra.Command, _ []string) error {
	return fmt.Errorf("not yet connected to gRPC client")
}

func runServerLiveness(_ *cobra.Command, _ []string) error {
	return fmt.Errorf("not yet connected to gRPC client")
}

func runServerReadiness(_ *cobra.Command, _ []string) error {
	return fmt.Errorf("not yet connected to gRPC client")
}
