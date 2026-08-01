package commands

import (
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/samber/oops"
	"github.com/spf13/cobra"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client/template"
)

// renderDrainLimit bounds how many entries the render command's WatchHosts
// drain loop will accumulate before refusing the whole snapshot. It is a
// package-level VARIABLE, not a const, so a test can lower it to drive the
// refusal path instead of seeding 50,000 host entries — a Go const cannot be
// lowered at runtime (review L1). It is a floor: plan 03 replaces it with
// the configurable limits.max_stream_entries ceiling. It exists so render is
// never exposed to unbounded accumulation in the waves between this plan
// and plan 03 (review L8).
var renderDrainLimit = 50_000

// newRenderCmd creates the "render" command: it renders host data through a
// caller-supplied text/template (TMPL-01), entirely client-side (D-01).
func newRenderCmd() *cobra.Command {
	var (
		templatePath string
		outPath      string
	)

	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render host data through a caller-supplied template",
		Long:  "Render host data through a caller-supplied text/template file and write the result to stdout or --out.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read and parse the template BEFORE opening any connection, so
			// a malformed template fails without touching the server.
			src, err := os.ReadFile(templatePath)
			if err != nil {
				return oops.Wrapf(err, "reading template %s", templatePath)
			}
			tmpl, err := template.Parse(templatePath, string(src))
			if err != nil {
				return err
			}

			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()

			ctx, cancel := commandContext()
			defer cancel()

			stream, err := c.Hosts.WatchHosts(ctx)
			if err != nil {
				return oops.Wrapf(err, "opening WatchHosts stream")
			}
			if err := stream.Send(&hostsv1.WatchHostsRequest{Follow: false}); err != nil {
				return oops.Wrapf(err, "sending WatchHosts request")
			}
			if err := stream.CloseSend(); err != nil {
				return oops.Wrapf(err, "closing WatchHosts send side")
			}

			var entries []*hostsv1.HostEntry
			var complete *hostsv1.SnapshotComplete
			for {
				resp, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return oops.Wrapf(err, "receiving WatchHosts response")
				}
				if e := resp.GetEntry(); e != nil {
					if len(entries) >= renderDrainLimit {
						return oops.Errorf("snapshot exceeds render drain limit of %d entries", renderDrainLimit)
					}
					entries = append(entries, e)
				}
				if c := resp.GetComplete(); c != nil {
					complete = c
				}
			}
			if complete == nil {
				return oops.Errorf("WatchHosts stream ended without a snapshot terminator")
			}

			data := template.FromProto(entries, complete)
			rendered, err := template.Render(tmpl, data)
			if err != nil {
				return err
			}

			if outPath == "" {
				_, err = cmd.OutOrStdout().Write(rendered)
				return err
			}
			return oops.Errorf("not implemented")
		},
	}

	cmd.Flags().StringVar(&templatePath, "template", "", "path to a text/template file (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "artifact output path (default: stdout)")
	_ = cmd.MarkFlagRequired("template")

	return cmd
}
