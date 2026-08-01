package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/samber/oops"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/client"
	"github.com/fzymgc-house/router-hosts/internal/client/output"
)

// addHostSubcommands attaches all host CRUD subcommands to the parent.
func addHostSubcommands(parent *cobra.Command) {
	parent.AddCommand(newHostAddCmd())
	parent.AddCommand(newHostGetCmd())
	parent.AddCommand(newHostUpdateCmd())
	parent.AddCommand(newHostDeleteCmd())
	parent.AddCommand(newHostListCmd())
	parent.AddCommand(newHostSearchCmd())
}

// --- host add ---

func newHostAddCmd() *cobra.Command {
	var (
		ip       string
		hostname string
		comment  string
		tags     []string
		aliases  []string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new host entry",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()

			req := &hostsv1.AddHostRequest{
				IpAddress: ip,
				Hostname:  hostname,
				Tags:      tags,
				Aliases:   aliases,
			}
			if comment != "" {
				req.Comment = &comment
			}

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.AddHost(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "adding host")
			}

			if Flags.Quiet {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), resp.GetId())
				return nil
			}

			return output.RenderHosts(cmd.OutOrStdout(), resolveFormat(), []*hostsv1.HostEntry{resp.GetEntry()})
		},
	}

	cmd.Flags().StringVar(&ip, "ip", "", "IP address (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname (required)")
	cmd.Flags().StringVar(&comment, "comment", "", "optional comment")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "comma-separated tags")
	cmd.Flags().StringSliceVar(&aliases, "aliases", nil, "comma-separated aliases")
	_ = cmd.MarkFlagRequired("ip")
	_ = cmd.MarkFlagRequired("hostname")

	return cmd
}

// --- host get ---

func newHostGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get a host entry by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			resp, err := c.Hosts.GetHost(ctx, &hostsv1.GetHostRequest{Id: args[0]})
			if err != nil {
				return oops.Wrapf(err, "getting host %s", args[0])
			}

			return output.RenderHosts(cmd.OutOrStdout(), resolveFormat(), []*hostsv1.HostEntry{resp.GetEntry()})
		},
	}
}

// --- host update ---

func newHostUpdateCmd() *cobra.Command {
	var (
		ip      string
		host    string
		comment string
		version string
		tags    []string
		aliases []string
	)

	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update an existing host entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()

			req := &hostsv1.UpdateHostRequest{
				Id: args[0],
			}

			if cmd.Flags().Changed("ip") {
				req.IpAddress = &ip
			}
			if cmd.Flags().Changed("hostname") {
				req.Hostname = &host
			}
			if cmd.Flags().Changed("comment") {
				req.Comment = &comment
			}
			if cmd.Flags().Changed("version") {
				req.ExpectedVersion = &version
			}
			if cmd.Flags().Changed("tags") {
				req.Tags = &hostsv1.TagsUpdate{Values: tags}
			}
			if cmd.Flags().Changed("aliases") {
				req.Aliases = &hostsv1.AliasesUpdate{Values: aliases}
			}

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.UpdateHost(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "updating host %s", args[0])
			}

			return output.RenderHosts(cmd.OutOrStdout(), resolveFormat(), []*hostsv1.HostEntry{resp.GetEntry()})
		},
	}

	cmd.Flags().StringVar(&ip, "ip", "", "new IP address")
	cmd.Flags().StringVar(&host, "hostname", "", "new hostname")
	cmd.Flags().StringVar(&comment, "comment", "", "new comment")
	cmd.Flags().StringVar(&version, "version", "", "expected version for optimistic concurrency")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "new tags (replaces existing)")
	cmd.Flags().StringSliceVar(&aliases, "aliases", nil, "new aliases (replaces existing)")

	return cmd
}

// --- host delete ---

func newHostDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a host entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			resp, err := c.Hosts.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: args[0]})
			if err != nil {
				return oops.Wrapf(err, "deleting host %s", args[0])
			}

			if !Flags.Quiet {
				if resp.GetSuccess() {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Deleted successfully")
				} else {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Delete returned success=false")
				}
			}
			return nil
		},
	}
}

// --- host list ---

func newHostListCmd() *cobra.Command {
	var (
		filter string
		limit  int32
		offset int32
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all host entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if err := c.Close(); err != nil {
					slog.Warn("closing client connection", "error", err)
				}
			}()

			req := &hostsv1.ListHostsRequest{}
			if cmd.Flags().Changed("filter") {
				req.Filter = &filter
			}
			if cmd.Flags().Changed("limit") {
				req.Limit = &limit
			}
			if cmd.Flags().Changed("offset") {
				req.Offset = &offset
			}

			ctx, cancel := commandContext()
			defer cancel()

			stream, err := c.Hosts.ListHosts(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "listing hosts")
			}

			entries, err := collectHostStream(stream, limitsFrom(c))
			if err != nil {
				return err
			}

			return output.RenderHosts(cmd.OutOrStdout(), resolveFormat(), entries)
		},
	}

	cmd.Flags().StringVar(&filter, "filter", "", "filter expression")
	cmd.Flags().Int32Var(&limit, "limit", 0, "max entries to return")
	cmd.Flags().Int32Var(&offset, "offset", 0, "entries to skip")

	return cmd
}

// --- host search ---

func newHostSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search host entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			stream, err := c.Hosts.SearchHosts(ctx, &hostsv1.SearchHostsRequest{
				Query: args[0],
			})
			if err != nil {
				return oops.Wrapf(err, "searching hosts")
			}

			entries, err := collectSearchStream(stream, limitsFrom(c))
			if err != nil {
				return err
			}

			return output.RenderHosts(cmd.OutOrStdout(), resolveFormat(), entries)
		},
	}
}

// --- helpers ---

// commandContext returns a context with a 30-second timeout for gRPC calls.
func commandContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// resolveFormat determines the output format from flags and TTY detection.
func resolveFormat() string {
	if Flags.Format != "" {
		return strings.ToLower(Flags.Format)
	}
	return output.DetectFormat()
}

// streamLimits carries the entry-count and byte-size ceilings a collecting
// call site enforces, sourced from a single *client.Client so no call site
// can pass one bound and forget the other (D-14, TMPL-07, review L1).
type streamLimits struct {
	entries int
	bytes   int64
}

// limitsFrom packages the stream-collection ceilings c carries (see
// client.Client.MaxStreamEntries/MaxStreamBytes) for a collecting call site.
func limitsFrom(c *client.Client) streamLimits {
	return streamLimits{entries: c.MaxStreamEntries(), bytes: c.MaxStreamBytes()}
}

// streamLimitError reports that a stream's entry count reached limit before
// its terminator arrived. The response is refused outright — never
// truncated (D-14) — and the message names both ways to raise the bound.
func streamLimitError(limit int) error {
	return oops.Errorf(
		"server response exceeds the client entry limit of %d entries; refusing "+
			"the result rather than returning a truncated one — raise the limit "+
			"via the client config file's limits.max_stream_entries key or the "+
			"ROUTER_HOSTS_MAX_STREAM_ENTRIES environment variable",
		limit)
}

// streamByteLimitError reports that a stream's accumulated serialized size
// (proto.Size summed across received messages) crossed the byte budget
// before its terminator arrived. Independent of streamLimitError: a stream
// can trip this bound while its entry count stays far below limits.entries,
// because comment and tag text carry no length validation (review L1).
func streamByteLimitError(limit int64) error {
	return oops.Errorf(
		"server response exceeds the client byte limit of %d bytes; refusing "+
			"the result rather than returning a truncated one — raise the limit "+
			"via the client config file's limits.max_stream_bytes key or the "+
			"ROUTER_HOSTS_MAX_STREAM_BYTES environment variable",
		limit)
}

// collectHostStream drains a ListHosts server stream into a slice, refusing
// (nil slice, non-nil error) before the offending append if either bound in
// limits is crossed.
func collectHostStream(stream hostsv1.HostsService_ListHostsClient, limits streamLimits) ([]*hostsv1.HostEntry, error) {
	var entries []*hostsv1.HostEntry
	var totalBytes int64
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, oops.Wrapf(err, "receiving host entry")
		}
		if resp.GetEntry() != nil {
			if len(entries) >= limits.entries {
				return nil, streamLimitError(limits.entries)
			}
			size := int64(proto.Size(resp))
			if totalBytes+size > limits.bytes {
				return nil, streamByteLimitError(limits.bytes)
			}
			totalBytes += size
			entries = append(entries, resp.GetEntry())
		}
	}
	return entries, nil
}

// collectSearchStream drains a SearchHosts server stream into a slice,
// refusing (nil slice, non-nil error) before the offending append if either
// bound in limits is crossed.
func collectSearchStream(stream hostsv1.HostsService_SearchHostsClient, limits streamLimits) ([]*hostsv1.HostEntry, error) {
	var entries []*hostsv1.HostEntry
	var totalBytes int64
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, oops.Wrapf(err, "receiving search result")
		}
		if resp.GetEntry() != nil {
			if len(entries) >= limits.entries {
				return nil, streamLimitError(limits.entries)
			}
			size := int64(proto.Size(resp))
			if totalBytes+size > limits.bytes {
				return nil, streamByteLimitError(limits.bytes)
			}
			totalBytes += size
			entries = append(entries, resp.GetEntry())
		}
	}
	return entries, nil
}
