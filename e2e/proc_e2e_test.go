//go:build proc_e2e

package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
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
