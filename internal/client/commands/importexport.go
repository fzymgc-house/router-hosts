package commands

import (
	"errors"
	"fmt"
	"io"
	"os"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/samber/oops"
	"github.com/spf13/cobra"
)

const importChunkSize = 64 * 1024 // 64 KiB

// addImportExportSubcommands attaches import/export to the host parent.
func addImportExportSubcommands(parent *cobra.Command) {
	parent.AddCommand(newHostImportCmd())
	parent.AddCommand(newHostExportCmd())
}

// --- host import ---

func newHostImportCmd() *cobra.Command {
	var (
		format       string
		conflictMode string
		force        bool
	)

	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import hosts from a file",
		Long:  "Import host entries from a file. Supported formats: hosts (default), json, csv.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			file, err := os.Open(args[0])
			if err != nil {
				return oops.Wrapf(err, "opening import file %s", args[0])
			}
			defer func() { _ = file.Close() }()

			ctx, cancel := commandContext()
			defer cancel()

			stream, err := c.Hosts.ImportHosts(ctx)
			if err != nil {
				return oops.Wrapf(err, "starting import stream")
			}

			buf := make([]byte, importChunkSize)
			for {
				n, readErr := file.Read(buf)
				if n > 0 {
					isLast := readErr == io.EOF
					req := &hostsv1.ImportHostsRequest{
						Chunk:     buf[:n],
						LastChunk: isLast,
					}
					if format != "" {
						req.Format = &format
					}
					if conflictMode != "" {
						req.ConflictMode = &conflictMode
					}
					if force {
						req.Force = &force
					}

					if sendErr := stream.Send(req); sendErr != nil {
						return oops.Wrapf(sendErr, "sending import chunk")
					}
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					return oops.Wrapf(readErr, "reading import file")
				}
			}

			if err := stream.CloseSend(); err != nil {
				return oops.Wrapf(err, "closing import send stream")
			}

			// Drain progress responses
			var lastResp *hostsv1.ImportHostsResponse
			for {
				resp, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return oops.Wrapf(err, "receiving import progress")
				}
				lastResp = resp
			}

			if lastResp != nil && !Flags.Quiet {
				fmt.Fprintf(cmd.OutOrStdout(),
					"Import complete: %d processed, %d created, %d updated, %d skipped, %d failed\n",
					lastResp.GetProcessed(),
					lastResp.GetCreated(),
					lastResp.GetUpdated(),
					lastResp.GetSkipped(),
					lastResp.GetFailed())

				if lastResp.GetError() != "" {
					fmt.Fprintf(cmd.OutOrStderr(), "Error: %s\n", lastResp.GetError())
				}
				for _, ve := range lastResp.GetValidationErrors() {
					fmt.Fprintf(cmd.OutOrStderr(), "  Validation: %s\n", ve)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "", "import format: hosts, json, csv (default: hosts)")
	cmd.Flags().StringVar(&conflictMode, "conflict-mode", "", "conflict handling: skip, replace, strict (default: skip)")
	cmd.Flags().BoolVar(&force, "force", false, "override strict mode validation")

	return cmd
}

// --- host export ---

func newHostExportCmd() *cobra.Command {
	var (
		format string
		outArg string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export hosts to a file or stdout",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()

			ctx, cancel := commandContext()
			defer cancel()

			exportFormat := format
			if exportFormat == "" {
				exportFormat = "hosts"
			}

			stream, err := c.Hosts.ExportHosts(ctx, &hostsv1.ExportHostsRequest{
				Format: exportFormat,
			})
			if err != nil {
				return oops.Wrapf(err, "starting export stream")
			}

			var w io.Writer = cmd.OutOrStdout()
			if outArg != "" && outArg != "-" {
				f, err := os.Create(outArg)
				if err != nil {
					return oops.Wrapf(err, "creating output file %s", outArg)
				}
				defer func() { _ = f.Close() }()
				w = f
			}

			for {
				resp, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return oops.Wrapf(err, "receiving export chunk")
				}
				if _, err := w.Write(resp.GetChunk()); err != nil {
					return oops.Wrapf(err, "writing export data")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "hosts", "export format: hosts, json, csv")
	cmd.Flags().StringVarP(&outArg, "output", "o", "", "output file (default: stdout)")

	return cmd
}
