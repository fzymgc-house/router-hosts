//go:build proc_e2e

package e2e_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcE2E_ColdStartWatchHonorsConfigFlag is the tracer for this suite:
// it proves, from OUTSIDE the process boundary, that `watch --config <path>`
// connects to the server named by that path and to no other — closing gap
// G-01-1's coverage half. Plan 01-10 supplied the fix (LoadClientConfig's
// layer-1 explicit-path branch); this is the only harness in this repo that
// can observe it from a real OS process boundary, which is the exact vantage
// point the original UAT failure occurred from.
//
// Two live servers, not one live and one dead: the UAT failure was a silent
// connection to a WORKING wrong server, and a dead decoy would let a
// connects-to-nothing implementation fail for the right reason by accident.
// Discrimination is on CONTENT (named-target.example present,
// decoy-target.example absent), which cannot pass accidentally.
func TestProcE2E_ColdStartWatchHonorsConfigFlag(t *testing.T) {
	bin := procBinaryPath(t)
	root := t.TempDir()

	pkiDir := filepath.Join(root, "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o700))
	bundle := newPKIBundle(t, pkiDir)
	clientCertPath, clientKeyPath := issueClientCert(t, bundle, "proc-e2e-tracer-client")

	serverADir := filepath.Join(root, "server-a")
	require.NoError(t, os.MkdirAll(serverADir, 0o700))
	addrA := fmt.Sprintf("127.0.0.1:%d", reserveLocalPort(t))
	cfgA := writeServerConfigFile(t, serverADir, addrA, bundle)
	srvA := startServerProcess(t, bin, cfgA, addrA, bundle)

	serverBDir := filepath.Join(root, "server-b")
	require.NoError(t, os.MkdirAll(serverBDir, 0o700))
	addrB := fmt.Sprintf("127.0.0.1:%d", reserveLocalPort(t))
	cfgB := writeServerConfigFile(t, serverBDir, addrB, bundle)
	srvB := startServerProcess(t, bin, cfgB, addrB, bundle)

	// The NAMED config: this is the one --config will point at.
	namedClientCfg := filepath.Join(root, "named.toml")
	writeClientConfigFile(t, namedClientCfg, srvA.addr, bundle.caCertPath, clientCertPath, clientKeyPath)

	// The DECOY config: valid, reachable, and placed on the sink's XDG
	// search path so it is genuinely discoverable and would be chosen by
	// pre-fix code that ignored --config and fell through to XDG discovery.
	xdgDir := filepath.Join(root, "xdg")
	decoyClientCfg := filepath.Join(xdgDir, "router-hosts", "client.toml")
	writeClientConfigFile(t, decoyClientCfg, srvB.addr, bundle.caCertPath, clientCertPath, clientKeyPath)

	env := hermeticEnv(t, xdgDir)

	// Seed server A (the named target) through the explicit named config.
	addOutA, addErrA := runCLI(t, bin, env,
		"--config", namedClientCfg, "host", "add",
		"--ip", "10.10.0.1", "--hostname", "named-target.example")
	require.NoError(t, addErrA, "seed server A: %s", addOutA)

	// Seed server B (the decoy target) through a SEPARATE explicit config
	// pointed at server B, kept outside the XDG dir so seeding it does not
	// itself exercise (or depend on) the discovery path under test.
	decoySeedCfg := filepath.Join(root, "decoy-seed.toml")
	writeClientConfigFile(t, decoySeedCfg, srvB.addr, bundle.caCertPath, clientCertPath, clientKeyPath)
	addOutB, addErrB := runCLI(t, bin, env,
		"--config", decoySeedCfg, "host", "add",
		"--ip", "10.10.0.2", "--hostname", "decoy-target.example")
	require.NoError(t, addErrB, "seed server B: %s", addOutB)

	tmplPath := examplesTemplatePath(t, "hosts.tmpl")
	sinkDir := filepath.Join(root, "sink")
	require.NoError(t, os.MkdirAll(sinkDir, 0o700))
	outPath := filepath.Join(sinkDir, "hosts.out")

	// Launch the sink against namedClientCfg with a child environment whose
	// XDG_CONFIG_HOME is xdgDir — the decoy is discoverable, and pre-fix
	// code would silently prefer it over the explicit --config path.
	sink := startSinkProcess(t, bin, namedClientCfg, tmplPath, outPath, env)

	content := waitForFileContent(t, outPath, 15*time.Second, func(s string) bool {
		return len(s) > 0
	})
	assert.Contains(t, content, "named-target.example",
		"rendered artifact must contain the NAMED server's host")
	assert.NotContains(t, content, "decoy-target.example",
		"rendered artifact must NOT contain the DECOY server's host — a silent connection to the decoy is the exact G-01-1 defect")

	status := waitForSidecar(t, sink.statusPath, 15*time.Second, func(st procSinkStatus) bool {
		return st.RenderedChangeID != ""
	})
	assert.Equal(t, 0, status.ConsecutiveFailures)
	assert.NotEmpty(t, status.RenderedChangeID)
}

// TestProcE2E_MissingExplicitConfigFailsLoudly is the process-level proof
// that an unusable --config never silently falls back to XDG discovery. A
// working config sits right where discovery would find it (deliberately —
// an empty XDG directory would let a broken implementation fail for an
// unrelated reason), yet the process must still die loudly and write
// nothing.
func TestProcE2E_MissingExplicitConfigFailsLoudly(t *testing.T) {
	bin := procBinaryPath(t)
	root := t.TempDir()

	pkiDir := filepath.Join(root, "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o700))
	bundle := newPKIBundle(t, pkiDir)
	clientCertPath, clientKeyPath := issueClientCert(t, bundle, "proc-e2e-failloud-client")

	serverDir := filepath.Join(root, "server")
	require.NoError(t, os.MkdirAll(serverDir, 0o700))
	addr := fmt.Sprintf("127.0.0.1:%d", reserveLocalPort(t))
	cfg := writeServerConfigFile(t, serverDir, addr, bundle)
	startServerProcess(t, bin, cfg, addr, bundle)

	// A fully VALID client config, discoverable via XDG — a fallback would
	// succeed and produce an artifact, which is what makes this test
	// meaningful.
	xdgDir := filepath.Join(root, "xdg")
	validXDGCfg := filepath.Join(xdgDir, "router-hosts", "client.toml")
	writeClientConfigFile(t, validXDGCfg, addr, bundle.caCertPath, clientCertPath, clientKeyPath)

	env := hermeticEnv(t, xdgDir)

	// The explicit --config path names a file inside a directory that does
	// not exist at all.
	missingCfgPath := filepath.Join(root, "does-not-exist", "client.toml")

	tmplPath := examplesTemplatePath(t, "hosts.tmpl")
	sinkDir := filepath.Join(root, "sink")
	require.NoError(t, os.MkdirAll(sinkDir, 0o700))
	outPath := filepath.Join(sinkDir, "hosts.out")

	out, runErr := runCLI(t, bin, env,
		"--config", missingCfgPath, "watch",
		"--template", tmplPath, "--out", outPath)

	// Three things, not one: exit code, output naming the path, and no
	// artifact. An exit code alone would not distinguish this from an
	// unrelated crash, and the missing artifact is what proves no fallback
	// connection to the valid XDG config was ever made.
	require.Error(t, runErr, "watch with a missing explicit --config must exit non-zero: %s", out)
	var exitErr *exec.ExitError
	require.True(t, errors.As(runErr, &exitErr), "expected an *exec.ExitError, got %T: %v", runErr, runErr)
	assert.NotEqual(t, 0, exitErr.ExitCode())
	assert.Contains(t, out, missingCfgPath,
		"process output must name the exact path that failed to load")

	_, statErr := os.Stat(outPath)
	assert.True(t, os.IsNotExist(statErr),
		"no artifact must be written when the explicit --config fails to load, got stat error: %v", statErr)
}

// TestProcE2E_ChangeIDPropagatesToSidecar proves artifact, sidecar, and
// change ID move together: a mutation made by a SEPARATE real CLI process
// (not the sink itself) reaches the sink's rendered artifact and advances
// the sidecar's rendered_change_id. Also exercises --config on a non-watch
// subcommand (host add), showing the fix is global to the client rather
// than special-cased for the sink.
func TestProcE2E_ChangeIDPropagatesToSidecar(t *testing.T) {
	bin := procBinaryPath(t)
	root := t.TempDir()

	pkiDir := filepath.Join(root, "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o700))
	bundle := newPKIBundle(t, pkiDir)
	clientCertPath, clientKeyPath := issueClientCert(t, bundle, "proc-e2e-changeid-client")

	serverDir := filepath.Join(root, "server")
	require.NoError(t, os.MkdirAll(serverDir, 0o700))
	addr := fmt.Sprintf("127.0.0.1:%d", reserveLocalPort(t))
	cfg := writeServerConfigFile(t, serverDir, addr, bundle)
	startServerProcess(t, bin, cfg, addr, bundle)

	xdgDir := filepath.Join(root, "xdg")
	clientCfg := filepath.Join(root, "client.toml")
	writeClientConfigFile(t, clientCfg, addr, bundle.caCertPath, clientCertPath, clientKeyPath)
	env := hermeticEnv(t, xdgDir)

	seedOut, seedErr := runCLI(t, bin, env,
		"--config", clientCfg, "host", "add",
		"--ip", "10.20.0.1", "--hostname", "initial-target.example")
	require.NoError(t, seedErr, "seed initial host: %s", seedOut)

	tmplPath := examplesTemplatePath(t, "hosts.tmpl")
	sinkDir := filepath.Join(root, "sink")
	require.NoError(t, os.MkdirAll(sinkDir, 0o700))
	outPath := filepath.Join(sinkDir, "hosts.out")

	sink := startSinkProcess(t, bin, clientCfg, tmplPath, outPath, env)

	firstContent := waitForFileContent(t, outPath, 30*time.Second, func(s string) bool {
		return strings.Contains(s, "initial-target.example")
	})
	firstStatus := waitForSidecar(t, sink.statusPath, 30*time.Second, func(st procSinkStatus) bool {
		return st.RenderedChangeID != ""
	})
	require.NotEmpty(t, firstStatus.RenderedChangeID, "first render must produce a change ID; last artifact:\n%s", firstContent)

	// A SEPARATE real CLI process — not the sink — performs the mutation.
	mutateOut, mutateErr := runCLI(t, bin, env,
		"--config", clientCfg, "host", "add",
		"--ip", "10.20.0.2", "--hostname", "added-after-start.example")
	require.NoError(t, mutateErr, "add second host via separate process: %s", mutateOut)

	secondContent := waitForFileContent(t, outPath, 30*time.Second, func(s string) bool {
		return strings.Contains(s, "added-after-start.example")
	})
	assert.Contains(t, secondContent, "initial-target.example",
		"the sink's artifact must still carry the original host after the mutation")

	secondStatus := waitForSidecar(t, sink.statusPath, 30*time.Second, func(st procSinkStatus) bool {
		return st.RenderedChangeID != "" && st.RenderedChangeID != firstStatus.RenderedChangeID
	})

	t.Logf("rendered_change_id: first=%s second=%s", firstStatus.RenderedChangeID, secondStatus.RenderedChangeID)
	assert.NotEqual(t, firstStatus.RenderedChangeID, secondStatus.RenderedChangeID,
		"rendered_change_id must advance: first=%q second=%q", firstStatus.RenderedChangeID, secondStatus.RenderedChangeID)
	assert.Equal(t, 0, secondStatus.ConsecutiveFailures)
	assert.Empty(t, secondStatus.LastError)

	// RenderedChangeID must not be trusted unless the artifact it describes
	// still exists (sinkstatus.go's documented contract) — confirm that
	// precondition holds at the moment this test relies on the field.
	_, statErr := os.Stat(outPath)
	assert.NoError(t, statErr, "artifact must still exist when trusting rendered_change_id")
}
