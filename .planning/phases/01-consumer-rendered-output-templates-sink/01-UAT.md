---
status: complete
phase: 01-consumer-rendered-output-templates-sink
source: [01-01-SUMMARY.md,01-02-SUMMARY.md 01-03-SUMMARY.md,01-04-SUMMARY.md 01-05-SUMMARY.md,01-06-SUMMARY.md 01-07-SUMMARY.md,01-08-SUMMARY.md 01-09-SUMMARY.md 01-10-SUMMARY.md,01-11-SUMMARY.md]
started: 2026-08-01T21:47:54Z
updated: 2026-08-02T00:40:00Z
---

# Phase 1 UAT — Consumer-Rendered Output

## Current Test

[testing complete]

## Tests

### 1. Cold Start Smoke Test

expected: |
  Kill any running router-hosts server and sink. Clear ephemeral state (temp
  DBs, sockets, rendered artifacts, sidecar status files). Start the server
  from scratch, then start `router-hosts watch` as a real CLI process against
  it. Server boots without errors, the sink connects over mTLS, renders its
  template, and writes the artifact plus sidecar. Note: e2e already automates
  *server* restart + reconnect (TestE2E_WatchSinkSurvivesServerRestart); this
  checks a genuinely fresh CLI process against a fresh server.
result: pass
previously: issue (blocker) — G-01-1, resolved by plans 01-10 + 01-11
previously_reported: "Cold start itself passes (server boots from empty DB, sink connects over real mTLS, renders artifact + sidecar, and a `host add` propagates with change_id moving off the zero sentinel). BUT the run exposed that `--config` is silently ignored by every client command: the sink dialed the operator's real router at 192.168.20.1:50051 instead of the 127.0.0.1:18443 in the config file passed via --config."
retest_reason: |
  Gap G-01-1 is reconciled as resolved (01-10-PLAN.md and 01-11-PLAN.md both
  declare closes_gaps: [G-01-1] and both have SUMMARYs). Re-run required to
  confirm the user-visible behavior, since the original failure was only
  observable from a real CLI process.
run_by: claude (tmux, real processes, not the in-process e2e harness)
retested: 2026-08-02
retest_evidence: |
  Fresh scratchpad PKI (openssl ECDSA CA, server leaf SAN localhost/127.0.0.1,
  client leaf CN=coldstart-client). TWO live servers as real OS processes in
  tmux, both from empty DBs:
    A = 127.0.0.1:18443, seeded ONLY with primary.lab (named by --config)
    B = 127.0.0.1:18444, seeded ONLY with decoy.lab (planted at
        $XDG_CONFIG_HOME/router-hosts/client.toml, i.e. ON the search path)

  MAIN TEST — `watch --config <real> --template … --out …`, with NO --server,
  --ca, --cert or --key on the command line (everything resolved from the file):
    * artifact rendered `10.0.0.1 primary.lab # server A only` — server A's
      content, NOT the decoy's
    * socket confirmation: watch pid 9679 held
      `127.0.0.1:59429->127.0.0.1:18443 (ESTABLISHED)`; server A pid 6447 held
      the matching inbound half; 18444 had ZERO established connections
    * sidecar written with contract_version 1, consecutive_failures 0,
      rendered_change_id 01KYZYSFJ8TJWGJKJSH00MPEKA
    * live propagation: `host add second.lab` on A moved the sidecar to
      01KYZYTFG047G1MHPMDFP5SK7J, count 1 -> 2, artifact rewrote with no
      operator action

  CONTROL 1 (anti-vacuity) — identical command with --config REMOVED rendered
  `10.9.9.9 decoy.lab # server B only`. The decoy WAS genuinely discoverable
  on the XDG path, so the main test's pass is the flag doing work, not the
  decoy being unreachable. This control reproduces the ORIGINAL G-01-1
  failure mode exactly.

  CONTROL 2 (loud failure) — `--config /nonexistent.toml` exited 1 with
  "loading client config …: no such file or directory" naming the path, wrote
  no artifact, and did NOT fall back to the XDG decoy — which was present and
  would have connected successfully.

  Incidental: the first template attempt used {{define "contract"}} instead of
  {{define "contract_version"}} and was refused before any gRPC call with a
  message naming the required block — test 7's enforcement firing for real.

### 2. [01-01/D1] A caller runs `router-hosts render --template ./x.tmpl` and gets host data rendered through their own template, no upstream code change

expected: A caller runs `router-hosts render --template ./x.tmpl` and gets host data rendered through their own template, no upstream code change
result: pass
source: automated
coverage_id: D1
requirement: TMPL-01
verified_by: unit internal/client/commands/render_test.go#TestRender_TemplateEndToEnd

### 3. [01-01/D2] Template top-level value is a struct exposing .Entries plus .Count, .GeneratedAt, .ContractVersion, .ChangeID, never a bare slice; each entry exposes IPAddress, Hostname, Aliases, Tags, Comment

expected: Template top-level value is a struct exposing .Entries plus .Count, .GeneratedAt, .ContractVersion, .ChangeID, never a bare slice; each entry exposes IPAddress, Hostname, Aliases, Tags, Comment
result: pass
source: automated
coverage_id: D2
requirement: TMPL-02
verified_by: unit internal/client/template/template_test.go#TestTemplateRender_HappyPath,TestTemplateRender_CountAndGeneratedAt,TestTemplateRender_ChangeIDIsRenderable

### 4. [01-01/D3] A template referencing a field that does not exist fails with a Go error instead of rendering empty

expected: A template referencing a field that does not exist fails with a Go error instead of rendering empty
result: pass
source: automated
coverage_id: D3
requirement: TMPL-03
verified_by: unit internal/client/template/template_test.go#TestTemplateRender_UndefinedFieldFails

### 5. [01-01/D4] --out writes the artifact through temp-file-plus-rename; a render failure leaves a pre-existing artifact byte-identical; internal/atomicfile.Write is the only write-and-rename helper reachable from internal/server

expected: --out writes the artifact through temp-file-plus-rename; a render failure leaves a pre-existing artifact byte-identical; internal/atomicfile.Write is the only write-and-rename helper reachable from internal/server
result: pass
source: automated
coverage_id: D4
requirement: TMPL-04
verified_by: unit internal/atomicfile/atomicfile_test.go#TestAtomicWrite_NewFile,TestAtomicWrite_OverwritesExisting,TestAtomicWrite_CleansUpTmp,TestAtomicWrite_InvalidPath; internal/client/commands/render_test.go#TestRender_WritesArtifactToOut,TestRender_FailurePreservesArtifact

### 6. [01-01/D5] WatchHosts streams one HostEntry per entry then exactly one SnapshotComplete terminator; the change ID is derived strictly before ListAll (a lower bound), is stable for unchanged state, advances monotonically across mutations, and reports the zero-ULID sentinel on an empty store

expected: WatchHosts streams one HostEntry per entry then exactly one SnapshotComplete terminator; the change ID is derived strictly before ListAll (a lower bound), is stable for unchanged state, advances monotonically across mutations, and reports the zero-ULID sentinel on an empty store
result: pass
source: automated
coverage_id: D5
requirement: TMPL-08
verified_by: unit internal/server/watch_test.go#TestService_WatchHosts_OneShotSnapshot,TestService_WatchHosts_ChangeIDStableForUnchangedState,TestService_WatchHosts_ChangeIDAdvancesOnMutation,TestService_WatchHosts_ChangeIDEmptyStore,TestService_WatchHosts_FollowUnimplemented,TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries

### 7. [01-02/D1] A template lacking a contract-version declaration, or declaring one that does not exactly match the server's served version, is refused with no gRPC call and no write to --out even when supplied

expected: A template lacking a contract-version declaration, or declaring one that does not exactly match the server's served version, is refused with no gRPC call and no write to --out even when supplied
result: pass
source: automated
coverage_id: D1
requirement: TMPL-03
verified_by: unit internal/client/template/template_test.go#TestTemplateVersion_DeclaredFromNamedBlock,TestTemplateVersion_MissingBlockFails,TestTemplateVersion_ExactMatchOnly; unit internal/client/commands/render_test.go#TestRender_RefusesUndeclaredVersion,TestRender_RefusesVersionMismatch

### 8. [01-02/D2] Contract v1 publishes a sanitize template function backed by the same single implementation the server generators use; an entry's .Comment or .Tags element containing a newline never breaks out of a single-line comment through either path

expected: Contract v1 publishes a sanitize template function backed by the same single implementation the server generators use; an entry's .Comment or .Tags element containing a newline never breaks out of a single-line comment through either path
result: pass
source: automated
coverage_id: D2
requirement: TMPL-02
verified_by: unit internal/sanitize/sanitize_test.go#TestCommentField_CollapsesLF,TestCommentField_CollapsesCR,TestCommentField_LeavesOtherBytes; unit internal/client/template/template_test.go#TestTemplateFuncs_SanitizeCollapsesNewline,TestTemplateFuncs_RawFieldStillCarriesNewline,TestTemplateFuncs_UnknownFuncFailsParse,TestSanitizeParity_ServerAndTemplateAgree

### 9. [01-02/D4] Three worked examples (unbound.tmpl, dnsmasq.tmpl, hosts.tmpl) each declare contract version 1, sanitize every .Comment/.Tags emission, and unbound.tmpl reproduces the ADR router-hosts-bzg per-name static zone form byte-for-byte against a fixture

expected: Three worked examples (unbound.tmpl, dnsmasq.tmpl, hosts.tmpl) each declare contract version 1, sanitize every .Comment/.Tags emission, and unbound.tmpl reproduces the ADR router-hosts-bzg per-name static zone form byte-for-byte against a fixture
result: pass
source: automated
coverage_id: D4
requirement: TMPL-02
verified_by: unit internal/client/template/template_test.go#TestExampleTemplates_DeclareContractVersion,TestExampleTemplates_UnboundMatchesExpectedOutput,TestExampleTemplates_DnsmasqAndHostsRender,TestExampleTemplates_SanitizeComments

### 10. [01-02/D3] docs/reference/template-contract.md is the single authoritative, versioned definition of the field set, FuncMap, version declaration/enforcement, .ChangeID's lower-bound-with-eventual-convergence semantics (scoped to sink mode, with one-shot render stated separately), the amended TMPL-06 scope, and the three D-12a sink-cycle outcomes; registered in mkdocs nav and docs/reference/index.md

expected: |
  docs/reference/template-contract.md is the single authoritative, versioned definition of the field set, FuncMap, version declaration/enforcement, .ChangeID's lower-bound-with-eventual-convergence semantics (scoped to sink mode, with one-shot render stated separately), the amended TMPL-06 scope, and the three D-12a sink-cycle outcomes; registered in mkdocs nav and docs/reference/index.md
rationale: |
  Grep gates can prove specific claims are present and specific overclaims are absent, but whether the prose is accurate, complete, and readable to a consumer writing a template from scratch is a judgment call a human reviewer should make once, given how load-bearing the .ChangeID semantics section is for plan 07's D-21 client-side skip.
result: pass
coverage_id: D3
requirement: TMPL-02
reason: human_judgment

### 11. [01-03/D1] A config file that exists but is malformed, carries an unknown key, or fails validation produces a startup error instead of a silent fallback to defaults; an absent config file is still not an error

expected: A config file that exists but is malformed, carries an unknown key, or fails validation produces a startup error instead of a silent fallback to defaults; an absent config file is still not an error
result: pass
source: automated
coverage_id: D1
requirement: TMPL-07
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_NoFileIsNotAnError,TestLoadClientConfig_MalformedFileErrors,TestLoadClientConfig_UnknownKeyErrors,TestLoadClientConfig_UnreadableFileErrors,TestLoadClientConfig_EnvDoesNotMaskFileError

### 12. [01-03/D2] Every client-side loop that accumulates stream messages into a slice stops at a configurable, independently-checked entry count AND byte budget, both with safe defaults, both configurable via TOML/env/override

expected: Every client-side loop that accumulates stream messages into a slice stops at a configurable, independently-checked entry count AND byte budget, both with safe defaults, both configurable via TOML/env/override
result: pass
source: automated
coverage_id: D2
requirement: TMPL-07
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_LimitsFromFile,TestLoadClientConfig_LimitsBytesFromFile,TestLoadClientConfig_LimitsDefault,TestLoadClientConfig_LimitsFromEnv,TestLoadClientConfig_LimitsInvalid,TestLoadClientConfig_LimitsBytesInvalid; internal/client/client_test.go#TestClient_MaxStreamEntriesFromConfig,TestClient_MaxStreamEntriesDefaultsFromConn,TestClient_MaxStreamBytesFromConfig,TestClient_OptionOverridesConfiguredLimit

### 13. [01-03/D3] Exceeding either bound at collectHostStream, collectSearchStream, collectSnapshotStream, or render's WatchHosts drain returns a nil slice and a named error before the offending append — never a truncated result; a stream yielding few but abnormally large entries trips the byte budget while under the entry cap

expected: Exceeding either bound at collectHostStream, collectSearchStream, collectSnapshotStream, or render's WatchHosts drain returns a nil slice and a named error before the offending append — never a truncated result; a stream yielding few but abnormally large entries trips the byte budget while under the entry cap
result: pass
source: automated
coverage_id: D3
requirement: TMPL-07
verified_by: unit internal/client/commands/host_test.go#TestCollectHostStream_CapExceeded,TestCollectHostStream_AtCapSucceeds,TestCollectHostStream_ByteBudgetExceeded; internal/client/commands/snapshot_test.go#TestCollectSnapshotStream_CapExceeded; internal/client/commands/render_test.go#TestRender_CapExceededPreservesArtifact

### 14. [01-04/D1] ExportHosts frames its response into bounded exportChunkSize (64 KiB) messages instead of one unbounded send, giving the client real gRPC flow-control backpressure

expected: ExportHosts frames its response into bounded exportChunkSize (64 KiB) messages instead of one unbounded send, giving the client real gRPC flow-control backpressure
result: pass
source: automated
coverage_id: D1
requirement: TMPL-06
verified_by: unit internal/server/service_test.go#TestService_ExportHosts_ChunksLargePayloadHosts,TestService_ExportHosts_ChunksLargePayloadJSON,TestService_ExportHosts_ChunksLargePayloadCSV

### 15. [01-04/D2] Byte identity of all three export formats is proven by full-stream reconstruction (concatenating every chunk equals the un-chunked payload), not inferred from tests that read only the first response

expected: Byte identity of all three export formats is proven by full-stream reconstruction (concatenating every chunk equals the un-chunked payload), not inferred from tests that read only the first response
result: pass
source: automated
coverage_id: D2
requirement: TMPL-06
verified_by: unit internal/server/service_test.go#TestService_ExportHosts_ChunksLargePayloadHosts,TestService_ExportHosts_ChunksLargePayloadJSON,TestService_ExportHosts_ChunksLargePayloadCSV,TestService_ExportHosts_RepeatedCallsAreIdentical

### 16. [01-04/D3] The empty-inventory single-message contract is preserved (never zero messages), and the exact chunk-boundary cases (exactly one chunk at the boundary, exactly two with a one-byte second chunk just past it) are pinned both through the live RPC and against the extracted sendExportChunks helper

expected: The empty-inventory single-message contract is preserved (never zero messages), and the exact chunk-boundary cases (exactly one chunk at the boundary, exactly two with a one-byte second chunk just past it) are pinned both through the live RPC and against the extracted sendExportChunks helper
result: pass
source: automated
coverage_id: D3
requirement: TMPL-06
verified_by: unit internal/server/service_test.go#TestService_ExportHosts_EmptyInventorySendsOneChunk,TestService_ExportHosts_ExactChunkBoundary,TestService_ExportHosts_OneByteOverBoundary,TestSendExportChunks_EmptyDataSendsOneEmptyChunk,TestSendExportChunks_ExactChunkBoundary,TestSendExportChunks_OneByteOverBoundary

### 17. [01-04/D4] WatchHosts sends exactly one message per entry plus exactly one SnapshotComplete terminator, including on an empty store (zero entry messages, one terminator with count 0)

expected: WatchHosts sends exactly one message per entry plus exactly one SnapshotComplete terminator, including on an empty store (zero entry messages, one terminator with count 0)
result: pass
source: automated
coverage_id: D4
requirement: TMPL-06
verified_by: unit internal/server/watch_test.go#TestService_WatchHosts_StreamsPerEntry,TestService_WatchHosts_EmptyStoreSendsTerminatorOnly

### 18. [01-04/D5] gRPC keepalive is configured explicitly on both server (30s ping/10s timeout, no connection-lifetime limits, 15s minimum accepted client interval) and client (20s ping/10s timeout, pings without an active RPC), replacing grpc-go's two-hour default

expected: gRPC keepalive is configured explicitly on both server (30s ping/10s timeout, no connection-lifetime limits, 15s minimum accepted client interval) and client (20s ping/10s timeout, pings without an active RPC), replacing grpc-go's two-hour default
result: pass
source: automated
coverage_id: D5
requirement: TMPL-06
verified_by: unit internal/server/server_test.go#TestKeepalive_ServerParams,TestKeepalive_ServerEnforcementPolicy,TestKeepalive_ServerOptionsCount; internal/client/client_test.go#TestKeepalive_ClientParams,TestKeepalive_ClientIntervalRespectsServerMinTime

### 19. [01-04/D6] The operations guide documents both sides' keepalive parameters, the MinTime invariant, the deliberate absence of connection-lifetime limits, and that the client-side parameters apply fleet-wide (every CLI command) rather than only to sinks

expected: |
  The operations guide documents both sides' keepalive parameters, the MinTime invariant, the deliberate absence of connection-lifetime limits, and that the client-side parameters apply fleet-wide (every CLI command) rather than only to sinks
rationale: |
  Documentation content quality (clarity, correct framing of fleet-wide scope) is a prose judgment, not something a unit test asserts beyond the keyword greps already run during execution.
result: pass
coverage_id: D6
requirement: -
reason: human_judgment

### 20. [01-05/D1] commonNameFromContext extracts the mTLS-verified peer identity from a stream context, or returns a clear error for each of the four failure modes (no peer, non-TLS auth, empty chain list, empty first chain)

expected: commonNameFromContext extracts the mTLS-verified peer identity from a stream context, or returns a clear error for each of the four failure modes (no peer, non-TLS auth, empty chain list, empty first chain)
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: unit internal/server/peercn_test.go#TestCommonNameFromContext (5 subtests)

### 21. [01-05/D2] SinkHealth registry: per-consumer state survives Disconnect, write health and reload health stay independent (D-12a), the connected count is identity-free and floors at zero, identity-extraction failures are counted separately, duplicate CNs collapse last-writer-wins (stated and tested, review M6), and the registry is safe under concurrent access

expected: SinkHealth registry: per-consumer state survives Disconnect, write health and reload health stay independent (D-12a), the connected count is identity-free and floors at zero, identity-extraction failures are counted separately, duplicate CNs collapse last-writer-wins (stated and tested, review M6), and the registry is safe under concurrent access
result: pass
source: automated
coverage_id: D2
requirement: TMPL-08
verified_by: unit internal/server/sinkmetrics_test.go#TestSinkHealth_RecordAndSnapshot,TestSinkHealth_StateSurvivesDisconnect,TestSinkHealth_ConnectedCountFloorsAtZero,TestSinkHealth_ConnectNeedsNoIdentity,TestSinkHealth_ReloadFailureKeepsLastSuccess,TestSinkHealth_ConvergedWhenChangeIDMatches,TestSinkHealth_NotConvergedWithoutReportedChangeID,TestSinkHealth_EvictsOldestPastCeiling,TestSinkHealth_SnapshotIsACopy,TestSinkHealth_ConcurrentAccess,TestSinkHealth_IdentityFailureCounts,TestSinkHealth_DuplicateCNCollapsesLastWriterWins

### 22. [01-05/D3] Seven observable gauges project SinkHealth through the existing OTel pipeline at scrape time: per-identity last-seen/last-success/failures/reload-failed/converged (labelled only by cn), plus label-free connected and identity-failure counts; every instrument has a real observation point and the change ID never becomes a label

expected: Seven observable gauges project SinkHealth through the existing OTel pipeline at scrape time: per-identity last-seen/last-success/failures/reload-failed/converged (labelled only by cn), plus label-free connected and identity-failure counts; every instrument has a real observation point and the change ID never becomes a label
result: pass
source: automated
coverage_id: D3
requirement: TMPL-08
verified_by: unit internal/server/metrics_test.go#TestRegisterSinkGauges_RealProvider,TestRegisterSinkGauges_NilProviderNoop,TestRegisterSinkGauges_NilHealthNoop,TestRegisterSinkGauges_ConvergedReflectsChangeID,TestRegisterSinkGauges_ReloadFailedIsIndependentOfLastSuccess,TestRegisterSinkGauges_IdentityFailuresObservedWithoutAttributes

### 23. [01-06/D1] A host mutation wakes every open watcher with no polling; a burst of mutations produces at most one additional wake per busy watcher (deterministic coalescing proof) and the stream converges on the final state (at most N+1 snapshots for N mutations, final entries and change ID match store state)

expected: A host mutation wakes every open watcher with no polling; a burst of mutations produces at most one additional wake per busy watcher (deterministic coalescing proof) and the stream converges on the final state (at most N+1 snapshots for N mutations, final entries and change ID match store state)
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: unit internal/server/changenotify_test.go#TestChangeNotifier_ReleasesSubscriber,TestChangeNotifier_ReleasesAllSubscribers,TestChangeNotifier_SubscriptionAfterNotifyStillWaits,TestChangeNotifier_NotifyWithNoSubscribers,TestChangeNotifier_CoalescesBurst,TestChangeNotifier_ConcurrentUse; internal/server/watch_test.go#TestService_WatchHosts_FollowInitialSnapshot,TestService_WatchHosts_FollowPushesOnMutation,TestService_WatchHosts_FollowConvergesAfterBurst

### 24. [01-06/D2] Every path that can move MAX(event_id) — any host mutation on any deployment configuration, and a successful non-dry-run compaction that actually shrinks an aggregate — reaches exactly one of two notify call expressions; a dry run and a no-op compaction notify nobody

expected: Every path that can move MAX(event_id) — any host mutation on any deployment configuration, and a successful non-dry-run compaction that actually shrinks an aggregate — reaches exactly one of two notify call expressions; a dry run and a no-op compaction notify nobody
result: pass
source: automated
coverage_id: D2
requirement: TMPL-05
verified_by: unit internal/server/changenotify_test.go#TestService_RegenerateOutputs_NotifiesWithoutGenerators,TestService_CompactAggregates_Notifies,TestService_CompactAggregates_DryRunDoesNotNotify,TestService_CompactAggregates_NoOpDoesNotNotify

### 25. [01-06/D3] The follow-mode handler returns on the first error from either stream direction without ever joining a goroutine that may be blocked in Send or Recv, in both reviewer-identified windows (Send fails while Recv is idle; Recv sees EOF while Send is blocked on flow control), and repeated connect/disconnect churn returns the connected count to zero without accumulating goroutines

expected: The follow-mode handler returns on the first error from either stream direction without ever joining a goroutine that may be blocked in Send or Recv, in both reviewer-identified windows (Send fails while Recv is idle; Recv sees EOF while Send is blocked on flow control), and repeated connect/disconnect churn returns the connected count to zero without accumulating goroutines
result: pass
source: automated
coverage_id: D3
requirement: TMPL-05
verified_by: unit internal/server/watch_test.go#TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle,TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked,TestService_WatchHosts_FollowContextCancelReturns,TestService_WatchHosts_FollowChurnDoesNotAccumulate

### 26. [01-06/D4] A consumer status report (opening message or mid-stream) updates that consumer's health record keyed only by verified mTLS common name; an unverifiable identity still streams but records no per-identity health and increments a separate identity-failure counter; a client-reported change ID never influences what the server sends; the follow-mode snapshot change ID remains a strict lower bound on its entries

expected: A consumer status report (opening message or mid-stream) updates that consumer's health record keyed only by verified mTLS common name; an unverifiable identity still streams but records no per-identity health and increments a separate identity-failure counter; a client-reported change ID never influences what the server sends; the follow-mode snapshot change ID remains a strict lower bound on its entries
result: pass
source: automated
coverage_id: D4
requirement: TMPL-05
verified_by: unit internal/server/watch_test.go#TestService_WatchHosts_FollowRecordsStatus,TestService_WatchHosts_FollowRecordsOpeningStatus,TestService_WatchHosts_FollowWithoutPeerIdentityStillStreams,TestService_WatchHosts_FollowIgnoresReportedChangeIDForSendDecision,TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries

### 27. [01-06/D5] Sink health is wired into the real server startup path, constructed unconditionally before the metrics block so status recording works with or without OTel, with sink gauges registered immediately after the existing aggregate-event gauges when OTel is configured

expected: Sink health is wired into the real server startup path, constructed unconditionally before the metrics block so status recording works with or without OTel, with sink gauges registered immediately after the existing aggregate-event gauges when OTel is configured
result: pass
source: automated
coverage_id: D5
requirement: TMPL-05
verified_by: unit internal/client/commands/serve_wiring_test.go#TestConfigureMetricsAndHooks_SinkHealthWithMetrics,TestConfigureMetricsAndHooks_SinkHealthWithoutMetrics,TestConfigureMetricsAndHooks_SinkOptionAlwaysPresent

### 28. [01-07/D1] A long-lived watch keeps --out current as host data changes, with no polling; starting the command writes the artifact once immediately, and a mutation triggers a rewrite with no operator action

expected: A long-lived watch keeps --out current as host data changes, with no polling; starting the command writes the artifact once immediately, and a mutation triggers a rewrite with no operator action
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_WritesInitialArtifact,TestWatch_RewritesOnMutation

### 29. [01-07/D2] Entries are buffered until the SnapshotComplete terminator; a partial snapshot (entries with no terminator) is never rendered, and the artifact reset happens after every terminator and every error path so an interrupted stream cannot produce a truncated artifact

expected: Entries are buffered until the SnapshotComplete terminator; a partial snapshot (entries with no terminator) is never rendered, and the artifact reset happens after every terminator and every error path so an interrupted stream cannot produce a truncated artifact
result: pass
source: automated
coverage_id: D2
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_PartialSnapshotNotRendered

### 30. [01-07/D3] Every pre-write failure mode (cap exceeded, contract version mismatch, render error) leaves the previous artifact byte-identical and records the failure to the sidecar without touching last_success or rendered_change_id

expected: Every pre-write failure mode (cap exceeded, contract version mismatch, render error) leaves the previous artifact byte-identical and records the failure to the sidecar without touching last_success or rendered_change_id
result: pass
source: automated
coverage_id: D3
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_CapExceededPreservesArtifact,TestWatch_VersionMismatchPreservesArtifact,TestWatch_RenderErrorPreservesArtifactAndRecordsFailure; internal/client/commands/sinkstatus_test.go#TestSinkStatus_FailurePreservesLastSuccess,TestSinkStatus_FailurePreservesRenderedChangeID

### 31. [01-07/D4] D-12a's three-outcome model is implemented and distinguishable: a hook failure retains the NEWLY rendered artifact (never rolls back) and sets reload_failed alongside the new last_success, without incrementing consecutive_failures; a subsequent hook success clears reload_failed

expected: D-12a's three-outcome model is implemented and distinguishable: a hook failure retains the NEWLY rendered artifact (never rolls back) and sets reload_failed alongside the new last_success, without incrementing consecutive_failures; a subsequent hook success clears reload_failed
result: pass
source: automated
coverage_id: D4
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_HookFailureRetainsNewArtifact,TestWatch_SuccessRunsPostWriteHook; internal/client/commands/sinkstatus_test.go#TestSinkStatus_ReloadFailureKeepsWriteHealth,TestSinkStatus_ReloadSuccessClearsFlag

### 32. [01-07/D5] The D-21 client-side change-ID skip fires only when all three guards hold (ID match, artifact still exists, reload health not failed); an out-of-band artifact deletion is repaired despite a matching ID, and a failed reload is retried on the next identical snapshot rather than suppressed forever

expected: The D-21 client-side change-ID skip fires only when all three guards hold (ID match, artifact still exists, reload health not failed); an out-of-band artifact deletion is repaired despite a matching ID, and a failed reload is retried on the next identical snapshot rather than suppressed forever
result: pass
source: automated
coverage_id: D5
requirement: TMPL-08
verified_by: unit internal/client/commands/watch_test.go#TestWatch_SkipsRedundantRenderOnSameChangeID,TestWatch_RendersWhenArtifactMissingDespiteSameChangeID,TestWatch_RetriesHookWhileReloadFailed

### 33. [01-07/D6] The sidecar status file (D-11) is written atomically through internal/atomicfile, distinguishes write health from reload health as separate fields, and is read back faithfully; a missing file is not an error (first run), a corrupt file is; concurrent readers/writers of the health state produce no data race under -race

expected: The sidecar status file (D-11) is written atomically through internal/atomicfile, distinguishes write health from reload health as separate fields, and is read back faithfully; a missing file is not an error (first run), a corrupt file is; concurrent readers/writers of the health state produce no data race under -race
result: pass
source: automated
coverage_id: D6
requirement: TMPL-05
verified_by: unit internal/client/commands/sinkstatus_test.go#TestSinkStatus_WriteAndRead,TestSinkStatus_SuccessClearsError,TestSinkStatus_DefaultPath,TestSinkStatus_ReadMissingFileIsNotAnError,TestSinkStatus_ReadCorruptFileErrors,TestSinkStatus_ConcurrentAccess,TestSinkStatus_Adopt,TestSinkStatus_SetContractVersion

### 34. [01-07/D7] A post-write hook (D-16) exits zero returns no error, exits non-zero returns a named-exit-status error, outruns its timeout and is classified as a timeout (not a generic failure) via the same hookCtx.Err()-before-process-error ordering internal/server/hooks.go uses, and an empty command is a no-op

expected: A post-write hook (D-16) exits zero returns no error, exits non-zero returns a named-exit-status error, outruns its timeout and is classified as a timeout (not a generic failure) via the same hookCtx.Err()-before-process-error ordering internal/server/hooks.go uses, and an empty command is a no-op
result: pass
source: automated
coverage_id: D7
requirement: TMPL-05
verified_by: unit internal/client/commands/posthook_test.go#TestPostWriteHook_Success,TestPostWriteHook_NonZeroExit,TestPostWriteHook_Timeout,TestPostWriteHook_EmptyCommandIsNoop,TestPostWriteHook_DefaultTimeoutConstant

### 35. [01-07/D8] WatchPolicy is one exported, injectable value (backoff bounds, jitter, status interval) with no mutable production globals; a nil Jitter or zero-valued field normalizes safely; the --status-interval flag's own default comes from the resolved policy, and only an explicit flag change overrides it — verified RED against a literal 30s default

expected: WatchPolicy is one exported, injectable value (backoff bounds, jitter, status interval) with no mutable production globals; a nil Jitter or zero-valued field normalizes safely; the --status-interval flag's own default comes from the resolved policy, and only an explicit flag change overrides it — verified RED against a literal 30s default
result: pass
source: automated
coverage_id: D8
requirement: TMPL-05
verified_by: unit internal/client/commands/watchpolicy_test.go#TestWatchPolicy_Defaults,TestWatchPolicy_NormalizesZeroFields,TestWatchPolicy_NilJitterIsSafe,TestWatchPolicy_DefaultJitterInRange; internal/client/commands/watch_test.go#TestWatch_StatusIntervalDefaultsFromPolicy,TestWatch_ExplicitStatusIntervalFlagOverridesPolicy

### 36. [01-07/D9] The status-sender goroutine cannot outlive its session: runWatch derives a per-session cancellable context, cancels it explicitly before waiting (bounded) on the ticker's completion channel, and the wait is observed to actually depend on the ticker's own exit rather than merely being intended

expected: The status-sender goroutine cannot outlive its session: runWatch derives a per-session cancellable context, cancels it explicitly before waiting (bounded) on the ticker's completion channel, and the wait is observed to actually depend on the ticker's own exit rather than merely being intended
result: pass
source: automated
coverage_id: D9
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_StatusTickerStopsWithSession

### 37. [01-07/D10] A restarted consumer loads its sidecar at startup and adopts it only when the artifact it describes still exists; when the artifact is present the first identical snapshot is skipped (no hook run), and when the artifact is missing the loaded change ID is discarded and the hook runs

expected: A restarted consumer loads its sidecar at startup and adopts it only when the artifact it describes still exists; when the artifact is present the first identical snapshot is skipped (no hook run), and when the artifact is missing the loaded change ID is discarded and the hook runs
result: pass
source: automated
coverage_id: D10
requirement: TMPL-08
verified_by: unit internal/client/commands/watch_test.go#TestWatch_LoadsSidecarAtStartup

### 38. [01-07/D11] A stream ending in error triggers a reconnect after a bounded, exponentially-increasing, jittered wait; the wait resets to InitialBackoff based on the session's SnapshotWritten result (not its error), including when a session wrote successfully and only failed later; cancelling during a backoff wait returns promptly; a reconnect is byte-identical when nothing changed and resets the sidecar's consecutive-failure count on recovery

expected: A stream ending in error triggers a reconnect after a bounded, exponentially-increasing, jittered wait; the wait resets to InitialBackoff based on the session's SnapshotWritten result (not its error), including when a session wrote successfully and only failed later; cancelling during a backoff wait returns promptly; a reconnect is byte-identical when nothing changed and resets the sidecar's consecutive-failure count on recovery
result: pass
source: automated
coverage_id: D11
requirement: TMPL-05
verified_by: unit internal/client/commands/watch_test.go#TestWatch_ReconnectsAfterStreamError,TestWatch_ReconnectNoTruncation,TestWatch_BackoffResetsAfterSuccess,TestWatch_BackoffResetsAfterSuccessfulWriteEvenIfSessionLaterFails,TestWatch_ReconnectResetsConsecutiveFailures,TestWatch_CancelDuringBackoffReturnsPromptly

### 39. [01-07/D12] The sink reports status upstream (last_success, consecutive_failures, contract_version, rendered_change_id, reload_failed, last_reload_success) on the opening message and on a periodic ticker, on the same stream it already holds open

expected: |
  The sink reports status upstream (last_success, consecutive_failures, contract_version, rendered_change_id, reload_failed, last_reload_success) on the opening message and on a periodic ticker, on the same stream it already holds open
rationale: |
  This plan proves the client constructs and sends the correct SinkStatus payload at the right times (opening message, periodic ticker); a genuine end-to-end proof that the server records and exposes it correctly through metrics was plan 06's responsibility and is not re-verified here. Plan 08's e2e suite is the natural place for a full round-trip check with both halves live.
result: pass
verified_by_operator_run: |
  Empirically verified 2026-08-01 by real-process run (not the in-process harness):
  minimal OTLP/gRPC metrics receiver + `serve` with [metrics.otel] + `watch` as
  separate OS processes. All seven sink gauges arrived; per-sink gauges keyed by
  cn=coldstart-client (the literal client-cert CommonName). sinks_connected 0->1,
  sink_converged 0->1, sink_last_seen_timestamp_seconds advanced at a clean 2s
  cadence matching --status-interval 2s, which is what distinguishes the periodic
  ticker from a single opening-message report. Closes the round-trip half that
  plan 07 explicitly left unverified.
coverage_id: D12
requirement: TMPL-05
reason: human_judgment

### 40. [01-08/D1] The consumer-rendered path (Watch snapshot, follow-mode push, mTLS CN-keyed sink health, real server stop/restart with reconnect) is proven over a real, CA-verified TLS 1.3 connection, not only bufconn/insecure credentials

expected: The consumer-rendered path (Watch snapshot, follow-mode push, mTLS CN-keyed sink health, real server stop/restart with reconnect) is proven over a real, CA-verified TLS 1.3 connection, not only bufconn/insecure credentials
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: e2e e2e/e2e_test.go#TestE2E_WatchSnapshotOverMTLS,TestE2E_WatchPushesOnMutation,TestE2E_WatchSinkHealthKeyedByCN,TestE2E_WatchSinkSurvivesServerRestart

### 41. [01-08/D2] An operator-facing guide documents render/watch end to end: sidecar fields, change-ID convergence semantics, the D-12a reload-failure outcome, all seven sink gauges, and the one-CN-per-consumer deployment requirement; render/watch are added to the CLI reference

expected: An operator-facing guide documents render/watch end to end: sidecar fields, change-ID convergence semantics, the D-12a reload-failure outcome, all seven sink gauges, and the one-CN-per-consumer deployment requirement; render/watch are added to the CLI reference
result: pass
source: automated
coverage_id: D2
requirement: TMPL-05
verified_by: other rumdl check docs/guides/consumer-rendered-output.md docs/reference/cli.md (exit 0); rg-based field/flag/gauge existence checks in 01-08-PLAN.md acceptance criteria (all satisfied)

### 42. [01-08/D3] Two manual, deployment-level verifications (resolver reload, two-node convergence) plus the restart/no-reload-storm and reload-failure-diagnosis scenarios, which require a real unbound host and a second machine

expected: |
  Two manual, deployment-level verifications (resolver reload, two-node convergence) plus the restart/no-reload-storm and reload-failure-diagnosis scenarios, which require a real unbound host and a second machine
rationale: |
  This environment has no unbound host and no second machine. Recorded explicitly as NOT-RUN in 01-VALIDATION.md with reason, concrete steps, and the automated coverage that does exist for each, per operator decision at the Task 3 checkpoint (mirrors phase 9's OTel-scrape precedent).
result: skipped
reason: |
  Deferred by explicit operator decision (Task 3 checkpoint, reaffirmed at UAT
  close 2026-08-02): "skip/blocked - this is a great test but needs a harness
  and docker containers likely." Requires a real unbound host and a second
  machine, neither of which exists in this environment.
previously: blocked (blocked_by: other) — reclassified 2026-08-02
reclassified_reason: |
  Not a code defect and not a prerequisite that will clear on its own — an
  environmental gap the operator chose to defer, already formally recorded
  rather than dropped. Mirrors phase 9's OTel-scrape precedent.
existing_record: "Recorded NOT-RUN in 01-VALIDATION.md with concrete steps and the automated coverage that does exist, per the Task 3 checkpoint decision."
follow_up: "Deferred Follow-Ups entry (test 42) — containerize via docker-compose with a real unbound container plus two sink containers."
coverage_id: D3
requirement: -
reason: human_judgment

### 43. [01-09/D1] internal/eventid mints monotonically increasing ULIDs against a raisable floor (New/Seed/NewAfter), replacing CommandHandler's per-handler entropy and CompactAggregate's bare ulid.Make() seed

expected: internal/eventid mints monotonically increasing ULIDs against a raisable floor (New/Seed/NewAfter), replacing CommandHandler's per-handler entropy and CompactAggregate's bare ulid.Make() seed
result: pass
source: automated
coverage_id: D1
requirement: TMPL-08
verified_by: unit internal/eventid/eventid_test.go#TestEventID_StrictlyIncreasing,TestEventID_Unique,TestEventID_ConcurrentUse,TestEventID_SeedRaisesFloor,TestEventID_SeedIgnoresLowerValue,TestEventID_NewAfterAlwaysGreater,TestEventID_SwapDefaultRestores; unit internal/storage/sqlite/compaction_monotonic_test.go#TestCompactAggregate_AdvancesLatestEventID,TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum

### 44. [01-09/D2] storage.EventStore.LatestEventID and storage.ZeroChangeID give every backend a change-ID contract: the greatest event_id, or the zero-ULID sentinel on an empty log

expected: storage.EventStore.LatestEventID and storage.ZeroChangeID give every backend a change-ID contract: the greatest event_id, or the zero-ULID sentinel on an empty log
result: pass
source: automated
coverage_id: D2
requirement: TMPL-08
verified_by: unit internal/storage/storagetest/suite.go#TestEventStoreLatestEventID,TestEventStoreCompactionAdvancesLatestEventID (run via internal/storage/sqlite/compliance_test.go TestCompliance)

### 45. [01-09/D3] insertEvent's in-transaction ordering guard: no commit lands an event ID at or below the log's current maximum, from any append path, any caller, any mint order, or across a restart — including the zero-ULID-into-empty-store edge case

expected: insertEvent's in-transaction ordering guard: no commit lands an event ID at or below the log's current maximum, from any append path, any caller, any mint order, or across a restart — including the zero-ULID-into-empty-store edge case
result: pass
source: automated
coverage_id: D3
requirement: TMPL-08
verified_by: unit internal/storage/sqlite/eventid_guard_test.go#TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax,TestInsertEvent_ZeroIDIntoEmptyStoreRemints,TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints,TestAppendEventsBatch_AllLowerIDsStillAdvanceMax,TestInsertEvent_ConcurrentReverseCommitOrderAdvancesMax,TestInitialize_SeedsGeneratorFromPersistedLog; unit internal/storage/storagetest/suite.go#TestEventStoreAppendNeverLowersLatestEventID

### 46. [01-10/D1] An explicit --config path is loaded directly and wins over XDG auto-discovery

expected: An explicit --config path is loaded directly and wins over XDG auto-discovery
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_ExplicitPathBeatsXDG; internal/client/commands/connect_test.go#TestDefaultNewClientFromFlags_ConfigFlagSelectsFile

### 47. [01-10/D2] An unreadable, unparseable, or unknown-key explicit path fails loudly and never falls back to XDG

expected: An unreadable, unparseable, or unknown-key explicit path fails loudly and never falls back to XDG
result: pass
source: automated
coverage_id: D2
requirement: TMPL-05
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_ExplicitMissingPathFailsAndDoesNotFallBack,TestLoadClientConfig_ExplicitMalformedPathFails,TestLoadClientConfig_ExplicitUnknownKeyFails

### 48. [01-10/D3] An explicit load replaces the file layer wholesale — no field from an XDG-discovered decoy config survives

expected: An explicit load replaces the file layer wholesale — no field from an XDG-discovered decoy config survives
result: pass
source: automated
coverage_id: D3
requirement: TMPL-05
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_ExplicitPathDoesNotMergeXDGValues

### 49. [01-10/D4] Layer precedence unchanged: explicit config file < env vars < CLI value flags

expected: Layer precedence unchanged: explicit config file < env vars < CLI value flags
result: pass
source: automated
coverage_id: D4
requirement: TMPL-05
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_EnvBeatsExplicitConfigFile,TestLoadClientConfig_ServerOverrideBeatsExplicitConfigFile

### 50. [01-10/D5] An empty ConfigPath pointer behaves identically to unset, and tilde expansion runs on the explicit path

expected: An empty ConfigPath pointer behaves identically to unset, and tilde expansion runs on the explicit path
result: pass
source: automated
coverage_id: D5
requirement: TMPL-05
verified_by: unit internal/config/client_test.go#TestLoadClientConfig_EmptyConfigPathFallsBackToXDG,TestLoadClientConfig_ExplicitPathTildeExpanded

### 51. [01-10/D6] --config precedence and XDG search order documented for operators

expected: --config precedence and XDG search order documented for operators
result: pass
source: automated
coverage_id: D6
requirement: -
verified_by: other rumdl check docs/reference/cli.md docs/guides/consumer-rendered-output.md

### 52. [01-11/D1] A test launches the built router-hosts binary as a real OS process and observes that watch --config <path> connects to the server named in <path> and to no other, discriminated by content between two live servers

expected: A test launches the built router-hosts binary as a real OS process and observes that watch --config <path> connects to the server named in <path> and to no other, discriminated by content between two live servers
result: pass
source: automated
coverage_id: D1
requirement: TMPL-05
verified_by: e2e e2e/proc_e2e_test.go#TestProcE2E_ColdStartWatchHonorsConfigFlag

### 53. [01-11/D2] A watch process given an unreadable --config exits non-zero with the path in its output and writes no artifact, even with a valid config present on the XDG search path

expected: A watch process given an unreadable --config exits non-zero with the path in its output and writes no artifact, even with a valid config present on the XDG search path
result: pass
source: automated
coverage_id: D2
requirement: TMPL-05
verified_by: e2e e2e/proc_e2e_test.go#TestProcE2E_MissingExplicitConfigFailsLoudly

### 54. [01-11/D3] A host mutation made by a second real CLI process propagates to the sink's artifact and advances the sidecar's rendered_change_id

expected: A host mutation made by a second real CLI process propagates to the sink's artifact and advances the sidecar's rendered_change_id
result: pass
source: automated
coverage_id: D3
requirement: TMPL-05
verified_by: e2e e2e/proc_e2e_test.go#TestProcE2E_ChangeIDPropagatesToSidecar

### 55. [01-11/D4] task test:e2e remains build-independent; the new proc_e2e tag does not make the pre-existing in-process suite require a built binary

expected: task test:e2e remains build-independent; the new proc_e2e tag does not make the pre-existing in-process suite require a built binary
result: pass
source: automated
coverage_id: D4
requirement: -
verified_by: other task clean && task test:e2e (verified green with bin/ absent)

### 56. [01-11/D5] Both key proc_e2e tests were demonstrated to FAIL when plan 01-10's fix is reverted, and PASS again once restored

expected: Both key proc_e2e tests were demonstrated to FAIL when plan 01-10's fix is reverted, and PASS again once restored
result: pass
source: automated
coverage_id: D5
requirement: -
verified_by: e2e manual revert-and-observe cycle (01-11-SUMMARY.md Regression Demonstrations, both directions quoted)

### 57. [01-11/D6] Three-tier e2e story, the in-process blind spot, and the deferred container-harness extension points are documented

expected: Three-tier e2e story, the in-process blind spot, and the deferred container-harness extension points are documented
result: pass
source: automated
coverage_id: D6
requirement: -
verified_by: other rumdl check docs/contributing/testing.md

### 58. Gap-closure confirmation — plans 01-10 + 01-11

expected: |
  All 12 deliverables from the two gap-closure plans are deterministically
  covered by passing tests (no human-judgment items). Orchestrator re-ran the
  suites live during this UAT session rather than trusting the SUMMARYs:
  `task test` (race) green across all packages, and `task test:e2e:proc` green
  on all three real-process tests. Confirm this closes G-01-1.
result: pass
verified_by_orchestrator_run: |
  Re-ran live during this UAT session rather than trusting the SUMMARYs:

- `task test` (go test -race -count=1 ./...) — every package ok, no failures
- `task test:e2e:proc` — TestProcE2E_ColdStartWatchHonorsConfigFlag,
  TestProcE2E_MissingExplicitConfigFailsLoudly,
  TestProcE2E_ChangeIDPropagatesToSidecar all PASS (0.988s)
  Independently corroborated by the manual real-process cold start recorded
  under test 1, including a control that reproduces the original failure.

## Summary

total: 58
passed: 57
issues: 0
pending: 0
skipped: 1
blocked: 0

## Gaps

- gap_id: G-01-1
  truth: "`router-hosts watch --config <path>` connects to the server named in <path>"
  status: resolved
  resolved_by: 01-10-PLAN.md, 01-11-PLAN.md
  resolved_at: 2026-08-02
  reason: "User-visible: the sink ignored --config and dialed the operator's production router (192.168.20.1:50051) instead of the 127.0.0.1:18443 named in the file passed to --config."
  severity: blocker
  test: 1
  root_cause: "`Flags.Config` is bound at internal/client/commands/root.go:88 and never read anywhere in the repo (`rg 'Flags\\.Config' --type go` returns exactly that one write). `config.LoadClientConfig` resolves the file layer solely via `findClientConfigFile()`, an XDG/platform directory search (internal/config/client.go:113, :197), and `ClientConfigOverrides` (client.go:76-83) has no config-path field, so there is no plumbing by which an explicit path could win."
  artifacts:
  - path: "internal/client/commands/root.go"
    issue: "line 88 registers --config into Flags.Config; nothing consumes it"
  - path: "internal/config/client.go"
    issue: "LoadClientConfig ignores any caller-supplied path; findClientConfigFile only searches XDG dirs"
  missing:
  - "Add a config-path field to ClientConfigOverrides (or a LoadClientConfig path parameter) and plumb Flags.Config into it"
  - "When an explicit path is given, load THAT file and fail loudly if it is unreadable — never silently fall back to the XDG search"
  - "Regression test: explicit --config must win over a different config present on the XDG search path"
  - "Full real-process cold-start e2e (operator decision, 2026-08-01): a new build-tagged test that builds the binary, generates a CA/server/client chain, runs `serve` and `watch` as real OS processes, and asserts artifact + sidecar + change-ID propagation. Scope explicitly chosen over an in-process-only flag-resolution test, because the entire existing e2e suite constructs `server.Server` and calls `commands.NewRootCmd().SetArgs()` in-process and therefore cannot observe CLI flag plumbing at all — the exact blind spot that let this bug ship."
  notes: "Pre-existing (--config predates this phase; XDG auto-discovery landed in 0.8.0), but phase 1 materially raises the blast radius: `watch` is a long-lived sink whose natural deployment is N instances with per-instance config files, and the failure mode is connecting to the wrong server with the wrong certs rather than an error."
  discovered_by: "real-process cold start; structurally invisible to the in-process e2e harness, which bypasses CLI flag parsing entirely"

## Deferred Follow-Ups

- test: 42
  idea: "Containerize the manual deployment verifications: a docker-compose harness with a real unbound container plus two sink containers would make resolver-reload and two-node convergence automatable, removing the 'needs a second machine' blocker permanently."
  deferred_at: 2026-08-01
  raised_by: operator during UAT
  relates_to: "G-01-1's full real-process cold-start e2e — both want a process/container-level harness rather than the current fully in-process e2e suite; worth designing as one harness, not two."
