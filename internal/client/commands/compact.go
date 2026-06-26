package commands

import (
	"fmt"
	"log/slog"

	"github.com/samber/oops"
	"github.com/spf13/cobra"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

// newCompactCmd creates the "compact" command (single aggregate or --over N).
func newCompactCmd() *cobra.Command {
	var (
		over   int64
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "compact [aggregate-id]",
		Short: "Compact bloated aggregates (fold event log to a single event)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !cmd.Flags().Changed("over") {
				return oops.Errorf("provide an aggregate-id or --over N")
			}
			if len(args) == 1 && cmd.Flags().Changed("over") {
				return oops.Errorf("specify either an aggregate-id or --over, not both")
			}

			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if cerr := c.Close(); cerr != nil {
					slog.Warn("closing client connection", "error", cerr)
				}
			}()

			req := &hostsv1.CompactAggregatesRequest{DryRun: dryRun}
			if len(args) == 1 {
				req.Target = &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: args[0]}
			} else {
				req.Target = &hostsv1.CompactAggregatesRequest_OverThreshold{OverThreshold: over}
			}

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.CompactAggregates(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "compacting aggregates")
			}

			if !Flags.Quiet {
				verb := "compacted"
				if dryRun {
					verb = "would compact"
				}
				for _, a := range resp.GetCompacted() {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %d -> %d events (v%d)\n",
						verb, a.GetAggregateId(), a.GetEventsBefore(), a.GetEventsAfter(), a.GetVersion())
				}
				summary := "total events reclaimed"
				if dryRun {
					summary = "total events that would be reclaimed"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %d\n", summary, resp.GetTotalEventsReclaimed())
			}
			return nil
		},
	}

	cmd.Flags().Int64Var(&over, "over", 0, "compact every aggregate with more than N events")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be compacted without changing anything")
	return cmd
}
