package commands

import (
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/samber/oops"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/atomicfile"
	"github.com/fzymgc-house/router-hosts/internal/client/template"
)

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
			declaredVersion, err := template.DeclaredVersion(tmpl)
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

			limits := limitsFrom(c)
			var entries []*hostsv1.HostEntry
			var complete *hostsv1.SnapshotComplete
			var totalBytes int64
			for {
				resp, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return oops.Wrapf(err, "receiving WatchHosts response")
				}
				if e := resp.GetEntry(); e != nil {
					if len(entries) >= limits.entries {
						return streamLimitError(limits.entries)
					}
					size := int64(proto.Size(resp))
					if totalBytes+size > limits.bytes {
						return streamByteLimitError(limits.bytes)
					}
					totalBytes += size
					entries = append(entries, e)
				}
				if comp := resp.GetComplete(); comp != nil {
					complete = comp
				}
			}
			if complete == nil {
				return oops.Errorf("WatchHosts stream ended without a snapshot terminator")
			}
			if err := template.RequireVersion(declaredVersion, complete.GetContractVersion()); err != nil {
				return err
			}

			data := template.FromProto(entries, complete)
			rendered, err := template.Render(tmpl, data)
			if err != nil {
				return err
			}

			// Rendering completed into a buffer before any write is
			// attempted, so a render failure above returns before this
			// point — a pre-existing artifact at outPath is never touched
			// on that path (D-12).
			if outPath == "" {
				_, err = cmd.OutOrStdout().Write(rendered)
				return err
			}
			if err := atomicfile.Write(outPath, rendered); err != nil {
				return oops.Wrapf(err, "writing artifact %s", outPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&templatePath, "template", "", "path to a text/template file (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "artifact output path (default: stdout)")
	_ = cmd.MarkFlagRequired("template")

	return cmd
}
