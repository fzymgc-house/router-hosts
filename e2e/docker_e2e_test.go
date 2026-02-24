//go:build docker_e2e

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dockerImage     = "router-hosts-e2e:test"
	containerName   = "router-hosts-docker-e2e"
	containerPort   = "50051"
	startupTimeout  = 30 * time.Second
	shutdownTimeout = 10 * time.Second
)

// dockerEnv holds Docker E2E test resources.
type dockerEnv struct {
	tmpDir      string
	containerID string
	grpcAddr    string
	caCertPath  string
	clientCert  []byte
	clientKey   []byte
}

// TestDockerE2E_ImageBuildsAndServes verifies the Docker image builds from the
// multi-stage Dockerfile and the server starts, accepts mTLS connections, and
// handles basic CRUD operations.
func TestDockerE2E_ImageBuildsAndServes(t *testing.T) {
	requireDocker(t)

	env := buildAndStartContainer(t)
	ctx := context.Background()

	// Connect with mTLS
	conn := dialGRPCWithCerts(t, env.grpcAddr,
		mustReadFile(t, env.caCertPath),
		env.clientCert, env.clientKey,
	)
	defer func() { _ = conn.Close() }()

	client := hostsv1.NewHostsServiceClient(conn)

	// Liveness check
	_, err := client.Liveness(ctx, &hostsv1.LivenessRequest{})
	require.NoError(t, err, "liveness check should succeed")

	// Readiness check
	_, err = client.Readiness(ctx, &hostsv1.ReadinessRequest{})
	require.NoError(t, err, "readiness check should succeed")

	// Add a host
	addResp, err := client.AddHost(ctx, &hostsv1.AddHostRequest{
		IpAddress: "192.168.10.1",
		Hostname:  "docker-test.local",
		Tags:      []string{"docker-e2e"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, addResp.GetId())

	// List hosts — verify it exists
	stream, err := client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries := collectListHosts(t, stream)
	require.Len(t, entries, 1)
	assert.Equal(t, "192.168.10.1", entries[0].GetIpAddress())
	assert.Equal(t, "docker-test.local", entries[0].GetHostname())

	// Delete the host
	_, err = client.DeleteHost(ctx, &hostsv1.DeleteHostRequest{Id: addResp.GetId()})
	require.NoError(t, err)

	// Verify empty
	stream, err = client.ListHosts(ctx, &hostsv1.ListHostsRequest{})
	require.NoError(t, err)
	entries = collectListHosts(t, stream)
	assert.Empty(t, entries)
}

// TestDockerE2E_WrongCARejected verifies the containerized server rejects
// client certificates signed by an unknown CA.
func TestDockerE2E_WrongCARejected(t *testing.T) {
	requireDocker(t)

	env := buildAndStartContainer(t)
	ctx := context.Background()

	// Generate a completely separate CA and client cert
	wrongCACert, _, wrongCAKey := generateCA(t)
	wrongClientCert, wrongClientKey := generateCert(t, wrongCACert, wrongCAKey, false)

	// Use the server's real CA for root trust (so TLS handshake starts),
	// but client cert is from wrong CA — server should reject.
	serverCACertPEM := mustReadFile(t, env.caCertPath)

	conn := dialGRPCWithCerts(t, env.grpcAddr, serverCACertPEM, wrongClientCert, wrongClientKey)
	defer func() { _ = conn.Close() }()

	client := hostsv1.NewHostsServiceClient(conn)
	_, err := client.Liveness(ctx, &hostsv1.LivenessRequest{})
	require.Error(t, err, "RPC with wrong-CA client cert should fail")
}

// TestDockerE2E_OperatorBinaryExists verifies the operator binary is included
// in the Docker image and is executable.
func TestDockerE2E_OperatorBinaryExists(t *testing.T) {
	requireDocker(t)

	// Build image (reuses cached layers if already built in this test run)
	buildDockerImage(t)

	out, err := exec.Command("docker", "run", "--rm", "--entrypoint", "operator",
		dockerImage, "--help").CombinedOutput()
	// The operator --help may exit 0 or non-zero depending on implementation,
	// but the binary should at least be found and produce output.
	if err != nil {
		// If it failed, check it's not "not found" error
		require.NotContains(t, string(out), "not found",
			"operator binary should exist in image: %s", string(out))
	}
	assert.NotEmpty(t, out, "operator binary should produce output")
}

// requireDocker skips the test if Docker is not available.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found, skipping Docker E2E test")
	}
	// Verify Docker daemon is running
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running, skipping Docker E2E test")
	}
}

// buildDockerImage builds the Docker image from the project root Dockerfile.
func buildDockerImage(t *testing.T) {
	t.Helper()

	// Find project root (parent of e2e/)
	root := projectRoot(t)

	cmd := exec.Command("docker", "build", "-t", dockerImage, "-f", "Dockerfile", root)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker build failed:\n%s", string(out))
}

// buildAndStartContainer builds the image, generates certs, creates a config,
// starts the container, and waits for it to be ready.
func buildAndStartContainer(t *testing.T) *dockerEnv {
	t.Helper()

	buildDockerImage(t)

	tmpDir := t.TempDir()

	// Generate mTLS certificates
	ca, caCertPEM, caKeyPEM := generateCA(t)
	serverCertPEM, serverKeyPEM := generateCert(t, ca, caKeyPEM, true)
	clientCertPEM, clientKeyPEM := generateCert(t, ca, caKeyPEM, false)

	// Write certs to disk (for mounting into container)
	caCertPath := writePEM(t, tmpDir, "ca.crt", caCertPEM)
	writePEM(t, tmpDir, "server.crt", serverCertPEM)
	writePEM(t, tmpDir, "server.key", serverKeyPEM)

	// Write server config
	configContent := fmt.Sprintf(`[server]
bind_address = "0.0.0.0:%s"
hosts_file_path = "/tmp/hosts"

[database]
path = "/tmp/hosts.db"

[tls]
cert_path = "/certs/server.crt"
key_path = "/certs/server.key"
ca_cert_path = "/certs/ca.crt"
`, containerPort)

	configPath := filepath.Join(tmpDir, "server.toml")
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	require.NoError(t, err)

	// Start container
	// Use a unique name per test to avoid collisions
	name := fmt.Sprintf("%s-%d", containerName, time.Now().UnixNano())

	cmd := exec.Command("docker", "run", "-d",
		"--name", name,
		"-p", "0:"+containerPort,
		"-v", tmpDir+"/ca.crt:/certs/ca.crt:ro",
		"-v", tmpDir+"/server.crt:/certs/server.crt:ro",
		"-v", tmpDir+"/server.key:/certs/server.key:ro",
		"-v", configPath+":/etc/router-hosts/server.toml:ro",
		dockerImage,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker run failed:\n%s", string(out))

	containerID := strings.TrimSpace(string(out))

	t.Cleanup(func() {
		// Capture logs before removing
		logs, _ := exec.Command("docker", "logs", containerID).CombinedOutput()
		if t.Failed() {
			t.Logf("Container logs:\n%s", string(logs))
		}
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	// Get the mapped host port — docker port returns multiple lines (IPv4 + IPv6),
	// take only the first line.
	portOut, err := exec.Command("docker", "port", containerID, containerPort).Output()
	require.NoError(t, err, "failed to get container port mapping")
	lines := strings.Split(strings.TrimSpace(string(portOut)), "\n")
	hostAddr := strings.TrimSpace(lines[0])
	// docker port returns "0.0.0.0:XXXXX" or ":::XXXXX", normalize to localhost
	hostAddr = strings.Replace(hostAddr, "0.0.0.0", "127.0.0.1", 1)
	if strings.HasPrefix(hostAddr, ":::") {
		hostAddr = "127.0.0.1:" + strings.TrimPrefix(hostAddr, ":::")
	}

	env := &dockerEnv{
		tmpDir:      tmpDir,
		containerID: containerID,
		grpcAddr:    hostAddr,
		caCertPath:  caCertPath,
		clientCert:  clientCertPEM,
		clientKey:   clientKeyPEM,
	}

	// Wait for server to be ready
	waitForDockerServer(t, env)

	return env
}

// waitForDockerServer polls the containerized server until it accepts connections.
func waitForDockerServer(t *testing.T, env *dockerEnv) {
	t.Helper()

	caCertPEM := mustReadFile(t, env.caCertPath)
	deadline := time.Now().Add(startupTimeout)

	for time.Now().Before(deadline) {
		// Check container is still running
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", env.containerID).Output()
		if err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _ := exec.Command("docker", "logs", env.containerID).CombinedOutput()
			t.Fatalf("container exited before becoming ready:\n%s", string(logs))
		}

		conn := dialGRPCWithCerts(t, env.grpcAddr, caCertPEM, env.clientCert, env.clientKey)
		client := hostsv1.NewHostsServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = client.Liveness(ctx, &hostsv1.LivenessRequest{})
		cancel()
		_ = conn.Close()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", env.containerID).CombinedOutput()
	t.Fatalf("container did not become ready within %v:\n%s", startupTimeout, string(logs))
}

// projectRoot finds the project root by looking for go.mod.
func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (no go.mod found)")
		}
		dir = parent
	}
}

// mustReadFile reads a file and fails the test on error.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
