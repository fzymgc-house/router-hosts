//go:build proc_e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fzymgc-house/router-hosts/internal/testutil/wait"
	"github.com/stretchr/testify/require"
)

// This file, and proc_e2e_test.go alongside it, are the ONLY e2e suite in
// this repository that launches the shipped router-hosts binary as a real
// operating-system process on BOTH sides of the mTLS connection. The
// existing in-process suite (helpers_test.go, build tag "e2e") constructs a
// server object and drives a client through the root command inside the
// SAME test process; the Docker suite (docker_e2e_test.go) containerizes
// only the server side and still drives the client in-process. Neither
// crosses the CLI-flag-to-config-loading seam an operator actually hits
// when they run this binary from a shell, which is exactly the seam gap
// G-01-1 lived in. Certificate generation here is deliberately duplicated
// from helpers_test.go rather than shared, so this file never imports (and
// can never accidentally reintroduce) any in-process server construction.

// procBinaryPath resolves the built router-hosts binary. It fails hard with
// t.Fatalf rather than skipping when the binary is missing: a suite whose
// entire purpose is proving something about the SHIPPED BINARY must not
// quietly report success (or be silently excluded) when that binary does
// not exist. A skip here would be the same class of failure as gap G-01-1
// itself — a green report that tested nothing.
func procBinaryPath(t *testing.T) string {
	t.Helper()

	if v := os.Getenv("ROUTER_HOSTS_BIN"); v != "" {
		if _, err := os.Stat(v); err != nil {
			t.Fatalf("ROUTER_HOSTS_BIN=%s does not exist (%v); run `task build` or point ROUTER_HOSTS_BIN at a built binary", v, err)
		}
		abs, err := filepath.Abs(v)
		require.NoError(t, err)
		return abs
	}

	path := filepath.Join("..", "bin", "router-hosts")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("binary not found at %s (%v); run `task build` first", path, err)
	}
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	return abs
}

// pkiBundle holds a CA and a shared server leaf certificate, generated once
// per test and reused by every server process that test starts. Client
// leaves are minted separately by issueClientCert, one per CN.
type pkiBundle struct {
	dir            string
	caCert         *x509.Certificate
	caKeyPEM       []byte
	caCertPath     string
	serverCertPath string
	serverKeyPath  string
}

// newPKIBundle generates a self-signed CA and a server leaf (localhost DNS
// SAN plus 127.0.0.1/::1 IP SANs, server-auth EKU) and writes both to dir.
// Shape adapted from e2e/helpers_test.go's generateCA/generateCert, which
// are already proven against this server's TLS listener.
func newPKIBundle(t *testing.T, dir string) *pkiBundle {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{Organization: []string{"router-hosts proc_e2e Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	require.NoError(t, err)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	caCertPath := writeProcPEM(t, dir, "ca.crt", caCertPEM)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"router-hosts proc_e2e Test"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	serverCertPath := writeProcPEM(t, dir, "server.crt", serverCertPEM)
	serverKeyPath := writeProcPEM(t, dir, "server.key", serverKeyPEM)

	return &pkiBundle{
		dir:            dir,
		caCert:         caCert,
		caKeyPEM:       caKeyPEM,
		caCertPath:     caCertPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
	}
}

// issueClientCert mints a client-auth leaf signed by b's CA, with the
// caller-supplied CN, and writes it under b.dir. The CN is a required
// parameter (not hard-coded) because sink health is keyed by mTLS CN: a
// future two-node convergence harness (deferred, see the plan's
// forward-compat mandate) needs two distinct CNs, and a function that mints
// only one would be unextendable.
func issueClientCert(t *testing.T, b *pkiBundle, cn string) (certPath, keyPath string) {
	t.Helper()

	caKeyBlock, _ := pem.Decode(b.caKeyPEM)
	require.NotNil(t, caKeyBlock)
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"router-hosts proc_e2e Test"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, b.caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	fname := sanitizeFilename(cn)
	certPath = writeProcPEM(t, b.dir, fname+".crt", certPEM)
	keyPath = writeProcPEM(t, b.dir, fname+".key", keyPEM)
	return certPath, keyPath
}

// sanitizeFilename maps a CN onto a safe filename component.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// writeProcPEM writes PEM data to dir/name and returns the path.
func writeProcPEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// reserveLocalPort binds loopback on port 0 to obtain an available port,
// then closes the listener and returns the port number.
//
// ACCEPTED TOCTOU WINDOW (threat T-01-G1-12, disposition accept): the port
// could in principle be claimed by another process between this Close and
// the server process's own bind. This is bounded, not ignored: every server
// launcher polls for real readiness with a real deadline and a loud, named
// failure rather than assuming success. The rejected alternative — parsing
// the bound port out of server log output — was rejected because it
// couples the harness to log formatting instead of to the process's actual
// protocol behavior, which is a worse long-term dependency.
func reserveLocalPort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve local port")
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())
	return port
}

// writeServerConfigFile writes a server TOML config to dir/server.toml,
// binding to addr, and returns the path. addr is a parameter (never
// assumed to be loopback), and the file is written to an arbitrary
// directory — a container harness can mount the same directory and pass a
// container-network address without touching this function.
func writeServerConfigFile(t *testing.T, dir, addr string, b *pkiBundle) string {
	t.Helper()

	hostsPath := filepath.Join(dir, "hosts")
	dbPath := filepath.Join(dir, "hosts.db")

	content := fmt.Sprintf(`[server]
bind_address = %q
hosts_file_path = %q

[database]
path = %q

[tls]
cert_path = %q
key_path = %q
ca_cert_path = %q
`, addr, hostsPath, dbPath, b.serverCertPath, b.serverKeyPath, b.caCertPath)

	path := filepath.Join(dir, "server.toml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// writeClientConfigFile writes a client TOML config to path, pointing at
// addr, and returns path. Like writeServerConfigFile, addr and path are
// both parameters — nothing here assumes loopback or a fixed directory
// layout, so a container harness can reuse this verbatim.
func writeClientConfigFile(t *testing.T, path, addr, caPath, certPath, keyPath string) string {
	t.Helper()

	content := fmt.Sprintf(`[server]
address = %q

[tls]
cert_path = %q
key_path = %q
ca_cert_path = %q
`, addr, certPath, keyPath, caPath)

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// serverProc is a handle on a real `router-hosts serve` OS process.
type serverProc struct {
	addr   string
	cmd    *exec.Cmd
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	stop   func()
}

// startServerProcess launches `router-hosts serve --config cfgPath` as a
// real OS process via os/exec, polls until addr accepts TCP connections
// with a bounded deadline, and registers a t.Cleanup that stops the process
// (signal, bounded wait, force-kill) and dumps captured output on failure.
// It never builds a server.Server, a service implementation, or any other
// in-process construct — the process boundary is the entire interface.
func startServerProcess(t *testing.T, bin, cfgPath, addr string, b *pkiBundle) *serverProc {
	t.Helper()
	_ = b // reserved for a future TLS-aware readiness check; TCP-level readiness is sufficient today

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "serve", "--config", cfgPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}

	require.NoError(t, cmd.Start(), "start server process")

	sp := &serverProc{addr: addr, cmd: cmd, stdout: &stdout, stderr: &stderr}

	stopped := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(stopped)
	}()

	sp.stop = func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-stopped
		}
	}

	t.Cleanup(func() {
		sp.stop()
		if t.Failed() {
			t.Logf("server process (%s) stdout:\n%s", addr, stdout.String())
			t.Logf("server process (%s) stderr:\n%s", addr, stderr.String())
		}
	})

	waitForProcAddr(t, addr)
	return sp
}

// waitForProcAddr polls addr with a plain TCP dial until a connection
// succeeds or a ten-second deadline passes, at which point it fails loudly
// and by name rather than hanging — this is the readiness backstop for
// reserveLocalPort's accepted TOCTOU window.
func waitForProcAddr(t *testing.T, addr string) {
	t.Helper()

	wait.Until(t, 10*time.Second, 50*time.Millisecond,
		"server at "+addr+" to accept a TCP connection",
		func() bool {
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		},
	)
}

// sinkProc is a handle on a real `router-hosts watch` OS process. Multiple
// concurrent sinkProc values are safe: each owns its own outPath and
// statusPath, so starting a second sink is a second call to
// startSinkProcess, never a refactor.
type sinkProc struct {
	outPath    string
	statusPath string
	cmd        *exec.Cmd
	stdout     *bytes.Buffer
	stderr     *bytes.Buffer
	stop       func()
}

// startSinkProcess launches `router-hosts --config clientCfgPath watch
// --template tmplPath --out outPath` as a real OS process with the given
// explicit environment, and registers a t.Cleanup that stops it the same
// way startServerProcess does. It does not wait for readiness itself —
// callers observe readiness through the artifact and sidecar, which is
// what the sink actually promises to produce.
func startSinkProcess(t *testing.T, bin, clientCfgPath, tmplPath, outPath string, env []string) *sinkProc {
	t.Helper()

	statusPath := outPath + ".status" // mirrors defaultStatusPath in internal/client/commands/sinkstatus.go

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin,
		"--config", clientCfgPath,
		"watch",
		"--template", tmplPath,
		"--out", outPath,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = env

	require.NoError(t, cmd.Start(), "start sink process")

	sp := &sinkProc{outPath: outPath, statusPath: statusPath, cmd: cmd, stdout: &stdout, stderr: &stderr}

	stopped := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(stopped)
	}()

	sp.stop = func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-stopped
		}
	}

	t.Cleanup(func() {
		sp.stop()
		if t.Failed() {
			t.Logf("sink process (%s) stdout:\n%s", outPath, stdout.String())
			t.Logf("sink process (%s) stderr:\n%s", outPath, stderr.String())
		}
	})

	return sp
}

// runCLI runs bin with args and env to completion (bounded by a 30-second
// context) and returns combined stdout+stderr plus the exit error. Used for
// one-shot subcommands: `host add` to seed servers, and the fail-loud
// negative test.
func runCLI(t *testing.T, bin string, env []string, args ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// hermeticEnv builds the explicit child-process environment for a CLI
// invocation. This is load-bearing (T-01-G1-09) and must not be skipped:
//   - XDG_CONFIG_HOME is set to xdgDir, the caller's chosen discovery root.
//   - HOME is set to a FRESH temp directory, so the ~/.config fallback and
//     the darwin ~/Library/Application Support fallback
//     (clientConfigSearchPaths, internal/config/client.go) cannot reach a
//     developer's real config.
//   - Every ROUTER_HOSTS_* env var the client config loader consults is
//     blanked explicitly, not merely omitted, so a test cannot accidentally
//     pass on one machine because of that machine's shell environment.
//
// The child process receives exactly this slice as its environment (never
// the parent's inherited environment plus overrides), so a test that
// accidentally inherited a developer's real config would fail loudly rather
// than passing for the wrong reason.
func hermeticEnv(t *testing.T, xdgDir string) []string {
	t.Helper()

	homeDir := t.TempDir()

	return []string{
		"PATH=" + os.Getenv("PATH"),
		"XDG_CONFIG_HOME=" + xdgDir,
		"HOME=" + homeDir,
		"ROUTER_HOSTS_SERVER=",
		"ROUTER_HOSTS_CERT=",
		"ROUTER_HOSTS_KEY=",
		"ROUTER_HOSTS_CA=",
		"ROUTER_HOSTS_MAX_STREAM_ENTRIES=",
		"ROUTER_HOSTS_MAX_STREAM_BYTES=",
	}
}

// procSinkStatus is a local mirror of the sidecar JSON contract
// (internal/client/commands/sinkstatus.go's unexported sinkStatus), kept
// deliberately separate rather than reaching into that unexported type.
type procSinkStatus struct {
	LastSuccess         time.Time `json:"last_success"`
	LastError           string    `json:"last_error"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	ContractVersion     string    `json:"contract_version"`
	RenderedChangeID    string    `json:"rendered_change_id"`
	ReloadFailed        bool      `json:"reload_failed"`
	LastReloadSuccess   time.Time `json:"last_reload_success"`
}

// waitForFileContent polls path until it exists and its content satisfies
// pred, or deadline passes — in which case it fails with the last observed
// content (or read error) in the message, never a bare "condition not met".
func waitForFileContent(t *testing.T, path string, deadline time.Duration, pred func(string) bool) string {
	t.Helper()

	return wait.UntilValue(t, deadline, 100*time.Millisecond,
		"content of "+path,
		func() (string, error) {
			data, err := os.ReadFile(path)
			return string(data), err
		},
		pred,
	)
}

// waitForSidecar polls path, parsing it as procSinkStatus JSON on every
// attempt, until pred is satisfied or deadline passes — failing with the
// last observed sidecar JSON (or read/parse error) in the message.
func waitForSidecar(t *testing.T, path string, deadline time.Duration, pred func(procSinkStatus) bool) procSinkStatus {
	t.Helper()

	return wait.UntilValue(t, deadline, 100*time.Millisecond,
		"sidecar status at "+path,
		func() (procSinkStatus, error) {
			data, err := os.ReadFile(path)
			if err != nil {
				return procSinkStatus{}, err
			}
			var st procSinkStatus
			if err := json.Unmarshal(data, &st); err != nil {
				return procSinkStatus{}, err
			}
			return st, nil
		},
		pred,
	)
}

// examplesTemplatePath resolves a shipped example template relative to the
// e2e package directory, so tests render through a real published example
// rather than an inline string — proving the shipped examples work from a
// cold start too.
func examplesTemplatePath(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "examples", "templates", name)
	abs, err := filepath.Abs(path)
	require.NoError(t, err)
	_, statErr := os.Stat(abs)
	require.NoError(t, statErr, "shipped example template not found: %s", abs)
	return abs
}
