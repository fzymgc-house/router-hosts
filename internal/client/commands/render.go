package commands

import (
	"github.com/samber/oops"
	"github.com/spf13/cobra"
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return oops.Errorf("not implemented")
		},
	}

	cmd.Flags().StringVar(&templatePath, "template", "", "path to a text/template file (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "artifact output path (default: stdout)")
	_ = cmd.MarkFlagRequired("template")

	return cmd
}
