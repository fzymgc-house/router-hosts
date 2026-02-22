package commands

import (
	"errors"
	"fmt"
	"io"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client/output"
	"github.com/samber/oops"
	"github.com/spf13/cobra"
)

// addSnapshotSubcommands attaches all snapshot subcommands to the parent.
func addSnapshotSubcommands(parent *cobra.Command) {
	parent.AddCommand(newSnapshotCreateCmd())
	parent.AddCommand(newSnapshotListCmd())
	parent.AddCommand(newSnapshotRollbackCmd())
	parent.AddCommand(newSnapshotDeleteCmd())
}

// --- snapshot create ---

func newSnapshotCreateCmd() *cobra.Command {
	var (
		name    string
		trigger string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a database snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			req := &hostsv1.CreateSnapshotRequest{
				Name:    name,
				Trigger: trigger,
			}

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.CreateSnapshot(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "creating snapshot")
			}

			if Flags.Quiet {
				fmt.Fprintln(cmd.OutOrStdout(), resp.GetSnapshotId())
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"Snapshot created: %s (entries: %d)\n",
				resp.GetSnapshotId(), resp.GetEntryCount())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "snapshot name (auto-generated if empty)")
	cmd.Flags().StringVar(&trigger, "trigger", "manual", "trigger reason")

	return cmd
}

// --- snapshot list ---

func newSnapshotListCmd() *cobra.Command {
	var (
		limit  uint32
		offset uint32
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all snapshots",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			req := &hostsv1.ListSnapshotsRequest{
				Limit:  limit,
				Offset: offset,
			}

			ctx, cancel := commandContext()
			defer cancel()

			stream, err := c.Hosts.ListSnapshots(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "listing snapshots")
			}

			snapshots, err := collectSnapshotStream(stream)
			if err != nil {
				return err
			}

			return output.RenderSnapshots(cmd.OutOrStdout(), resolveFormat(), snapshots)
		},
	}

	cmd.Flags().Uint32Var(&limit, "limit", 0, "max snapshots to return")
	cmd.Flags().Uint32Var(&offset, "offset", 0, "snapshots to skip")

	return cmd
}

// --- snapshot rollback ---

func newSnapshotRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <snapshot-id>",
		Short: "Rollback to a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.RollbackToSnapshot(ctx, &hostsv1.RollbackToSnapshotRequest{
				SnapshotId: args[0],
			})
			if err != nil {
				return oops.Wrapf(err, "rolling back to snapshot %s", args[0])
			}

			if !Flags.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(),
					"Rollback %s: restored %d entries (backup: %s)\n",
					successStr(resp.GetSuccess()),
					resp.GetRestoredEntryCount(),
					resp.GetNewSnapshotId())
			}
			return nil
		},
	}
}

// --- snapshot delete ---

func newSnapshotDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <snapshot-id>",
		Short: "Delete a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.DeleteSnapshot(ctx, &hostsv1.DeleteSnapshotRequest{
				SnapshotId: args[0],
			})
			if err != nil {
				return oops.Wrapf(err, "deleting snapshot %s", args[0])
			}

			if !Flags.Quiet {
				if resp.GetSuccess() {
					fmt.Fprintln(cmd.OutOrStdout(), "Snapshot deleted successfully")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "Delete returned success=false")
				}
			}
			return nil
		},
	}
}

// --- helpers ---

func collectSnapshotStream(stream hostsv1.HostsService_ListSnapshotsClient) ([]*hostsv1.Snapshot, error) {
	var snapshots []*hostsv1.Snapshot
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, oops.Wrapf(err, "receiving snapshot")
		}
		if resp.GetSnapshot() != nil {
			snapshots = append(snapshots, resp.GetSnapshot())
		}
	}
	return snapshots, nil
}

func successStr(ok bool) string {
	if ok {
		return "succeeded"
	}
	return "failed"
}
