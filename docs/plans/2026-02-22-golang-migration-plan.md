# Go Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate router-hosts from Rust to Go, preserving event sourcing + CQRS, gRPC/mTLS, and all core functionality with a simplified SQLite-only storage layer.

**Architecture:** Monorepo with `internal/` packages, two binaries (`cmd/router-hosts` + `cmd/operator`), pure Go SQLite via modernc.org, Cobra+BubbleTea CLI, lego ACME, kubebuilder operator.

**Tech Stack:** Go 1.23+, gRPC, buf, modernc.org/sqlite, Cobra, BubbleTea, Lip Gloss, samber/oops, lego, kubebuilder, OpenTelemetry, GoReleaser

**Design doc:** `docs/plans/2026-02-22-golang-migration-design.md`

---

## Phase 0: Scaffolding & Tooling

### Task 1: Initialize Go module and directory structure

**Files:**

- Create: `go.mod`
- Create: `cmd/router-hosts/main.go`
- Create: `internal/.gitkeep` (placeholder)
- Create: `.golangci.yml`

**Step 1: Initialize Go module**

Run:

```bash
go mod init github.com/fzymgc-house/router-hosts
```

Expected: `go.mod` created with module path.

**Step 2: Create directory skeleton**

Create all directories from the design doc:

```bash
mkdir -p cmd/router-hosts cmd/operator
mkdir -p internal/domain internal/storage/sqlite/migrations internal/storage/sqlite/queries
mkdir -p internal/server internal/client/commands internal/client/tui internal/client/output
mkdir -p internal/validation internal/config internal/acme
mkdir -p operator/api/v1alpha1 operator/controllers operator/config
mkdir -p api/v1 e2e
```

**Step 3: Create minimal main.go**

File: `cmd/router-hosts/main.go`

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("router-hosts")
	os.Exit(0)
}
```

**Step 4: Verify it builds**

Run: `go build ./cmd/router-hosts`
Expected: Binary produced, no errors.

**Step 5: Create `.golangci.yml`**

```yaml
run:
  timeout: 5m

linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused
    - gosimple
    - ineffassign
    - typecheck
    - revive
    - gocritic
    - gofumpt
    - misspell
    - nilerr
    - errorlint
    - exhaustive
    - prealloc

linters-settings:
  revive:
    rules:
      - name: exported
        arguments:
          - "checkPrivateReceivers"
  exhaustive:
    default-signifies-exhaustive: true

issues:
  exclude-use-default: false
```

**Step 6: Commit**

```text
chore: initialize Go module and directory structure

Scaffold the Go project layout with cmd/, internal/, and tooling
config. This is the foundation for the Rust-to-Go migration.
```

---

### Task 2: Set up Taskfile for Go

**Files:**

- Create: `Taskfile.go.yml` (temporary, will replace `Taskfile.yml` after Rust removal)

**Step 1: Write Go Taskfile**

File: `Taskfile.go.yml`

```yaml
version: '3'

vars:
  IMAGE_NAME: ghcr.io/fzymgc-house/router-hosts
  IMAGE_TAG: '{{.IMAGE_TAG | default "dev"}}'
  LOCAL_IMAGE: 'router-hosts:e2e-local'

tasks:
  build:
    desc: Build all binaries
    cmds:
      - go build ./cmd/router-hosts
      - go build ./cmd/operator

  build:release:
    desc: Build all binaries with optimizations
    cmds:
      - go build -ldflags="-s -w" -o bin/router-hosts ./cmd/router-hosts
      - go build -ldflags="-s -w" -o bin/operator ./cmd/operator

  test:
    desc: Run all tests
    cmds:
      - go test ./... -race -count=1

  test:coverage:
    desc: Run tests with coverage report
    cmds:
      - go test ./... -race -coverprofile=coverage.out -covermode=atomic
      - go tool cover -html=coverage.out -o coverage.html

  test:coverage:ci:
    desc: Run tests with coverage (CI mode - enforces 80% threshold)
    cmds:
      - go test ./... -race -coverprofile=coverage.out -covermode=atomic
      - |
        COVERAGE=$(go tool cover -func=coverage.out | tail -1 | awk '{print $3}' | tr -d '%')
        echo "Coverage: ${COVERAGE}%"
        if [ "$(echo "${COVERAGE} < 80" | bc)" -eq 1 ]; then
          echo "FAIL: Coverage ${COVERAGE}% is below 80% threshold"
          exit 1
        fi

  lint:
    desc: Run all linters
    cmds:
      - golangci-lint run ./...
      - buf lint
      - buf format --diff --exit-code

  fmt:
    desc: Format all code
    cmds:
      - gofumpt -w .
      - buf format -w

  proto:generate:
    desc: Generate Go code from protobuf definitions
    cmds:
      - buf generate

  ci:
    desc: Run full CI pipeline locally
    cmds:
      - task: lint
      - task: test
```

**Step 2: Verify task list works**

Run: `task --taskfile Taskfile.go.yml --list`
Expected: All tasks listed.

**Step 3: Commit**

```text
build: add Go Taskfile for development commands

Mirrors the Rust Taskfile patterns with Go equivalents.
Will replace Taskfile.yml after Rust code is archived.
```

---

### Task 3: Configure buf for Go code generation

**Files:**

- Modify: `buf.yaml` (if changes needed for Go)
- Create: `buf.gen.yaml`

**Step 1: Check current buf.yaml**

Read `buf.yaml` to see current config. We keep proto/ as-is for now.

**Step 2: Write buf.gen.yaml for Go**

File: `buf.gen.yaml`

```yaml
version: v2
plugins:
  - remote: buf.build/protocolbuffers/go
    out: api/v1
    opt:
      - paths=source_relative
  - remote: buf.build/grpc/go
    out: api/v1
    opt:
      - paths=source_relative
```

**Step 3: Run buf generate**

Run: `buf generate`
Expected: Go files generated in `api/v1/`.

**Step 4: Add generated files as dependency**

Run: `go mod tidy`
Expected: `google.golang.org/grpc` and `google.golang.org/protobuf` added to `go.mod`.

**Step 5: Verify generated code compiles**

Run: `go build ./api/...`
Expected: No errors.

**Step 6: Commit**

```text
build(proto): configure buf for Go code generation

Add buf.gen.yaml to generate Go protobuf and gRPC stubs
from existing proto definitions into api/v1/.
```

---

## Phase 1: Domain Model

### Task 4: Domain events and host aggregate types

**Files:**

- Create: `internal/domain/events.go`
- Create: `internal/domain/host.go`
- Create: `internal/domain/snapshot.go`
- Create: `internal/domain/errors.go`
- Create: `internal/domain/events_test.go`

**Step 1: Write domain error codes**

File: `internal/domain/errors.go`

```go
package domain

import "github.com/samber/oops"

// Error codes for domain operations. Mapped to gRPC status codes
// at the service layer.
const (
	CodeVersionConflict = "version_conflict"
	CodeNotFound        = "not_found"
	CodeDuplicate       = "duplicate_entry"
	CodeValidation      = "validation_failed"
	CodeInternal        = "internal"
)

// ErrNotFound creates a not-found error with entity context.
func ErrNotFound(entity string, id string) error {
	return oops.
		Code(CodeNotFound).
		In("domain").
		With("entity", entity).
		With("id", id).
		Errorf("%s not found: %s", entity, id)
}

// ErrDuplicate creates a duplicate-entry error.
func ErrDuplicate(ip, hostname string) error {
	return oops.
		Code(CodeDuplicate).
		In("domain").
		With("ip", ip).
		With("hostname", hostname).
		Errorf("duplicate entry: %s %s", ip, hostname)
}

// ErrVersionConflict creates a version-conflict error.
func ErrVersionConflict(aggregateID string, expected, actual string) error {
	return oops.
		Code(CodeVersionConflict).
		In("domain").
		With("aggregate_id", aggregateID).
		With("expected_version", expected).
		With("actual_version", actual).
		Errorf("version conflict for %s: expected %s, got %s", aggregateID, expected, actual)
}

// ErrValidation creates a validation error.
func ErrValidation(msg string) error {
	return oops.
		Code(CodeValidation).
		In("domain").
		Errorf("validation failed: %s", msg)
}
```

**Step 2: Write event types**

File: `internal/domain/events.go`

Port directly from Rust `types.rs:56-141`. JSON-serializable with type discriminator.

```go
package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// EventType identifies the kind of domain event.
type EventType string

const (
	EventHostCreated      EventType = "HostCreated"
	EventIpAddressChanged EventType = "IpAddressChanged"
	EventHostnameChanged  EventType = "HostnameChanged"
	EventCommentUpdated   EventType = "CommentUpdated"
	EventTagsModified     EventType = "TagsModified"
	EventAliasesModified  EventType = "AliasesModified"
	EventHostDeleted      EventType = "HostDeleted"
)

// HostEvent is a domain event for host entry changes.
// Serialized as JSON with a "type" discriminator field.
type HostEvent struct {
	Type EventType       `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Event payload types — one per EventType.

type HostCreatedData struct {
	IPAddress string   `json:"ip_address"`
	Hostname  string   `json:"hostname"`
	Aliases   []string `json:"aliases"`
	Comment   *string  `json:"comment"`
	Tags      []string `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
}

type IPAddressChangedData struct {
	OldIP     string    `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	ChangedAt time.Time `json:"changed_at"`
}

type HostnameChangedData struct {
	OldHostname string    `json:"old_hostname"`
	NewHostname string    `json:"new_hostname"`
	ChangedAt   time.Time `json:"changed_at"`
}

type CommentUpdatedData struct {
	OldComment *string   `json:"old_comment"`
	NewComment *string   `json:"new_comment"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type TagsModifiedData struct {
	OldTags    []string  `json:"old_tags"`
	NewTags    []string  `json:"new_tags"`
	ModifiedAt time.Time `json:"modified_at"`
}

type AliasesModifiedData struct {
	OldAliases []string  `json:"old_aliases"`
	NewAliases []string  `json:"new_aliases"`
	ModifiedAt time.Time `json:"modified_at"`
}

type HostDeletedData struct {
	IPAddress string    `json:"ip_address"`
	Hostname  string    `json:"hostname"`
	DeletedAt time.Time `json:"deleted_at"`
	Reason    *string   `json:"reason"`
}

// NewHostEvent creates a HostEvent from a typed payload.
func NewHostEvent(eventType EventType, data any) (HostEvent, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return HostEvent{}, fmt.Errorf("marshal event data: %w", err)
	}
	return HostEvent{Type: eventType, Data: raw}, nil
}

// EventEnvelope wraps an event with metadata (ID, aggregate, version).
type EventEnvelope struct {
	EventID     ulid.ULID `json:"event_id"`
	AggregateID ulid.ULID `json:"aggregate_id"`
	Event       HostEvent `json:"event"`
	Version     string    `json:"event_version"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   *string   `json:"created_by"`
}
```

**Step 3: Write host aggregate and snapshot types**

File: `internal/domain/host.go`

```go
package domain

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// HostEntry is the read-model projection of a host aggregate.
type HostEntry struct {
	ID        ulid.ULID
	IP        string
	Hostname  string
	Aliases   []string
	Comment   *string
	Tags      []string
	Version   string
	CreatedAt time.Time
	UpdatedAt time.Time
	Deleted   bool
}

// SearchFilter for querying host entries.
type SearchFilter struct {
	IPPattern       string
	HostnamePattern string
	Tags            []string
	Query           string // free-text search across all fields
}
```

File: `internal/domain/snapshot.go`

```go
package domain

import "time"

// Snapshot is a point-in-time capture of the hosts file.
type Snapshot struct {
	SnapshotID       string
	CreatedAt        time.Time
	HostsContent     string
	EntryCount       int32
	Trigger          string
	Name             string
	EventLogPosition *int64
}

// SnapshotMetadata is Snapshot without content (for listing).
type SnapshotMetadata struct {
	SnapshotID string
	CreatedAt  time.Time
	EntryCount int32
	Trigger    string
	Name       string
}
```

**Step 4: Write tests for event serialization**

File: `internal/domain/events_test.go`

```go
package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostEvent_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	comment := "Test server"

	data := HostCreatedData{
		IPAddress: "192.168.1.10",
		Hostname:  "server.local",
		Aliases:   []string{"srv"},
		Comment:   &comment,
		Tags:      []string{"prod"},
		CreatedAt: now,
	}

	event, err := NewHostEvent(EventHostCreated, data)
	require.NoError(t, err)
	assert.Equal(t, EventHostCreated, event.Type)

	// Deserialize back
	var decoded HostCreatedData
	err = json.Unmarshal(event.Data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, data.IPAddress, decoded.IPAddress)
	assert.Equal(t, data.Hostname, decoded.Hostname)
	assert.Equal(t, data.Aliases, decoded.Aliases)
	assert.Equal(t, *data.Comment, *decoded.Comment)
	assert.Equal(t, data.Tags, decoded.Tags)
}

func TestNewHostEvent_AllTypes(t *testing.T) {
	now := time.Now().UTC()
	reason := "cleanup"

	tests := []struct {
		name      string
		eventType EventType
		data      any
	}{
		{"HostCreated", EventHostCreated, HostCreatedData{
			IPAddress: "10.0.0.1", Hostname: "test.local",
			Aliases: nil, Comment: nil, Tags: nil, CreatedAt: now,
		}},
		{"IpAddressChanged", EventIpAddressChanged, IPAddressChangedData{
			OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now,
		}},
		{"HostnameChanged", EventHostnameChanged, HostnameChangedData{
			OldHostname: "old.local", NewHostname: "new.local", ChangedAt: now,
		}},
		{"CommentUpdated", EventCommentUpdated, CommentUpdatedData{
			OldComment: nil, NewComment: &reason, UpdatedAt: now,
		}},
		{"TagsModified", EventTagsModified, TagsModifiedData{
			OldTags: nil, NewTags: []string{"prod"}, ModifiedAt: now,
		}},
		{"AliasesModified", EventAliasesModified, AliasesModifiedData{
			OldAliases: nil, NewAliases: []string{"srv"}, ModifiedAt: now,
		}},
		{"HostDeleted", EventHostDeleted, HostDeletedData{
			IPAddress: "10.0.0.1", Hostname: "test.local",
			DeletedAt: now, Reason: &reason,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := NewHostEvent(tt.eventType, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.eventType, event.Type)
			assert.NotEmpty(t, event.Data)
		})
	}
}

func TestHostEvent_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	original, err := NewHostEvent(EventHostCreated, HostCreatedData{
		IPAddress: "192.168.1.1",
		Hostname:  "test.local",
		Aliases:   []string{},
		Comment:   nil,
		Tags:      []string{},
		CreatedAt: now,
	})
	require.NoError(t, err)

	// Full marshal/unmarshal cycle
	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded HostEvent
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Type, decoded.Type)
}

func TestHostEvent_BackwardCompat_MissingAliases(t *testing.T) {
	// Old events without aliases field should deserialize with nil/empty
	oldJSON := `{
		"ip_address": "192.168.1.1",
		"hostname": "test.local",
		"comment": null,
		"tags": [],
		"created_at": "2025-01-01T00:00:00Z"
	}`

	var data HostCreatedData
	err := json.Unmarshal([]byte(oldJSON), &data)
	require.NoError(t, err)
	assert.Empty(t, data.Aliases)
}
```

**Step 5: Run tests**

Run: `go test ./internal/domain/ -v -count=1`
Expected: All tests pass.

**Step 6: Commit**

```text
feat(domain): add event types, host aggregate, and error codes

Port domain model from Rust: 7 event types with JSON serialization,
HostEntry projection, Snapshot types, and oops error codes mapped
to gRPC status codes.
```

---

## Phase 2: Validation

### Task 5: IP and hostname validation

**Files:**

- Create: `internal/validation/validation.go`
- Create: `internal/validation/validation_test.go`

**Step 1: Write the validation tests first (TDD)**

File: `internal/validation/validation_test.go`

Port test cases from Rust `validation.rs:144-497`. Use table-driven tests.

```go
package validation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
)

func TestValidateIPAddress_ValidIPv4(t *testing.T) {
	valid := []string{
		"192.168.1.1", "10.0.0.1", "127.0.0.1", "255.255.255.255",
	}
	for _, ip := range valid {
		t.Run(ip, func(t *testing.T) {
			assert.NoError(t, ValidateIPAddress(ip))
		})
	}
}

func TestValidateIPAddress_InvalidIPv4(t *testing.T) {
	invalid := []string{
		"256.1.1.1", "192.168.1", "192.168.1.1.1", "not-an-ip", "",
	}
	for _, ip := range invalid {
		t.Run(ip, func(t *testing.T) {
			assert.Error(t, ValidateIPAddress(ip))
		})
	}
}

func TestValidateIPAddress_ValidIPv6(t *testing.T) {
	valid := []string{
		"::1", "fe80::1", "2001:0db8:85a3::8a2e:0370:7334", "::ffff:192.168.1.1",
	}
	for _, ip := range valid {
		t.Run(ip, func(t *testing.T) {
			assert.NoError(t, ValidateIPAddress(ip))
		})
	}
}

func TestValidateIPAddress_InvalidIPv6(t *testing.T) {
	invalid := []string{"gggg::1", "::::::"}
	for _, ip := range invalid {
		t.Run(ip, func(t *testing.T) {
			assert.Error(t, ValidateIPAddress(ip))
		})
	}
}

func TestValidateHostname_Valid(t *testing.T) {
	valid := []string{
		"localhost", "server.local", "my-server", "server123",
		"sub.domain.example.com", "a", "1", "123", "123.456",
	}
	for _, h := range valid {
		t.Run(h, func(t *testing.T) {
			assert.NoError(t, ValidateHostname(h))
		})
	}
}

func TestValidateHostname_Invalid(t *testing.T) {
	invalid := []string{
		"", "-invalid", "invalid-", "in..valid", "invalid_host",
		".invalid", "invalid.",
	}
	for _, h := range invalid {
		t.Run(h, func(t *testing.T) {
			assert.Error(t, ValidateHostname(h))
		})
	}
}

func TestValidateHostname_MaxLabelLength(t *testing.T) {
	// 63 chars = ok
	assert.NoError(t, ValidateHostname(strings.Repeat("a", 63)))
	// 64 chars = too long
	assert.Error(t, ValidateHostname(strings.Repeat("a", 64)))
}

func TestValidateHostname_MaxTotalLength(t *testing.T) {
	label := strings.Repeat("a", 63)
	// 63+1+63+1+63+1+61 = 253 = ok
	h253 := label + "." + label + "." + label + "." + strings.Repeat("a", 61)
	assert.Len(t, h253, 253)
	assert.NoError(t, ValidateHostname(h253))
	// 254 = too long
	h254 := label + "." + label + "." + label + "." + strings.Repeat("a", 62)
	assert.Len(t, h254, 254)
	assert.Error(t, ValidateHostname(h254))
}

func TestValidateAliases_Valid(t *testing.T) {
	assert.NoError(t, ValidateAliases([]string{}, "server.local"))
	assert.NoError(t, ValidateAliases([]string{"srv", "s.local"}, "server.local"))
}

func TestValidateAliases_MatchesHostname(t *testing.T) {
	err := ValidateAliases([]string{"srv", "server.local"}, "server.local")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "matches canonical hostname")
}

func TestValidateAliases_MatchesHostnameCaseInsensitive(t *testing.T) {
	err := ValidateAliases([]string{"SERVER.LOCAL"}, "server.local")
	assert.Error(t, err)
}

func TestValidateAliases_Duplicate(t *testing.T) {
	err := ValidateAliases([]string{"srv", "srv"}, "server.local")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidateAliases_DuplicateCaseInsensitive(t *testing.T) {
	err := ValidateAliases([]string{"srv", "SRV"}, "server.local")
	assert.Error(t, err)
}

func TestValidateAliases_IPAddressRejected(t *testing.T) {
	// IPv4
	err := ValidateAliases([]string{"192.168.1.1"}, "server.local")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP address")

	// IPv6
	err = ValidateAliases([]string{"::1"}, "server.local")
	assert.Error(t, err)
}

func TestValidateAliases_TooMany(t *testing.T) {
	aliases := make([]string, MaxAliasesPerEntry+1)
	for i := range aliases {
		aliases[i] = strings.Repeat("a", 5) + strings.Repeat("0", 3) // aliasNNN pattern
	}
	// Generate unique aliases
	for i := range aliases {
		aliases[i] = "alias" + strings.Repeat("a", i%50+1) + "x"
	}
	// Simplified: just generate enough unique ones
	aliases2 := make([]string, MaxAliasesPerEntry+1)
	for i := range aliases2 {
		aliases2[i] = fmt.Sprintf("alias%d", i)
	}
	err := ValidateAliases(aliases2, "server.local")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many")
}

func TestValidateAliases_ExactlyMax(t *testing.T) {
	aliases := make([]string, MaxAliasesPerEntry)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("alias%d", i)
	}
	assert.NoError(t, ValidateAliases(aliases, "server.local"))
}

// Property-based tests using rapid

func TestValidateIPAddress_Prop_ValidIPv4AlwaysParses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.IntRange(0, 255).Draw(t, "a")
		b := rapid.IntRange(0, 255).Draw(t, "b")
		c := rapid.IntRange(0, 255).Draw(t, "c")
		d := rapid.IntRange(0, 255).Draw(t, "d")
		ip := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		if err := ValidateIPAddress(ip); err != nil {
			t.Fatalf("valid IPv4 %s failed: %v", ip, err)
		}
	})
}

func TestValidateIPAddress_Prop_Consistent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ip := rapid.String().Draw(t, "ip")
		r1 := ValidateIPAddress(ip)
		r2 := ValidateIPAddress(ip)
		if (r1 == nil) != (r2 == nil) {
			t.Fatalf("inconsistent validation for %q", ip)
		}
	})
}

func TestValidateHostname_Prop_UnderscoreAlwaysFails(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.StringMatching(`[a-z]{1,5}`).Draw(t, "prefix")
		suffix := rapid.StringMatching(`[a-z]{1,5}`).Draw(t, "suffix")
		h := prefix + "_" + suffix
		if err := ValidateHostname(h); err == nil {
			t.Fatalf("underscore hostname %q should fail", h)
		}
	})
}
```

Note: add `import "fmt"` at the top alongside the other imports.

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/validation/ -v -count=1`
Expected: FAIL — `ValidateIPAddress`, `ValidateHostname`, etc. not defined.

**Step 3: Write implementation**

File: `internal/validation/validation.go`

```go
package validation

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/samber/oops"
)

const (
	// MaxAliasesPerEntry prevents resource exhaustion.
	MaxAliasesPerEntry = 50

	codeValidation = "validation_failed"
)

var labelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateIPAddress validates an IPv4 or IPv6 address string.
func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return oops.
			Code(codeValidation).
			With("ip", ip).
			Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ValidateHostname validates a DNS hostname per RFC 1035.
//
// Rules:
//   - Total length: 1-253 characters
//   - Labels separated by dots, each 1-63 characters
//   - Labels: alphanumeric and hyphens only
//   - Cannot start or end with hyphen or dot
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return validationErr("hostname cannot be empty")
	}
	if len(hostname) > 253 {
		return validationErr("hostname exceeds maximum length of 253 characters")
	}
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return validationErr("hostname cannot start or end with dot")
	}
	if strings.HasPrefix(hostname, "-") || strings.HasSuffix(hostname, "-") {
		return validationErr("hostname cannot start or end with hyphen")
	}

	for _, label := range strings.Split(hostname, ".") {
		if label == "" {
			return validationErr("hostname cannot contain consecutive dots")
		}
		if !labelRegex.MatchString(label) {
			return validationErr(fmt.Sprintf("invalid label '%s' in hostname", label))
		}
	}

	return nil
}

// ValidateAliases validates an alias list for a host entry.
func ValidateAliases(aliases []string, canonicalHostname string) error {
	if len(aliases) > MaxAliasesPerEntry {
		return oops.
			Code(codeValidation).
			With("count", len(aliases)).
			With("max", MaxAliasesPerEntry).
			Errorf("too many aliases: %d exceeds maximum of %d", len(aliases), MaxAliasesPerEntry)
	}

	seen := make(map[string]struct{}, len(aliases))

	for _, alias := range aliases {
		// Check for IP address first (more specific error)
		if net.ParseIP(alias) != nil {
			return oops.
				Code(codeValidation).
				With("alias", alias).
				Errorf("alias '%s' cannot be an IP address", alias)
		}

		if err := ValidateHostname(alias); err != nil {
			return err
		}

		if strings.EqualFold(alias, canonicalHostname) {
			return oops.
				Code(codeValidation).
				With("alias", alias).
				Errorf("alias '%s' matches canonical hostname", alias)
		}

		lower := strings.ToLower(alias)
		if _, exists := seen[lower]; exists {
			return oops.
				Code(codeValidation).
				With("alias", alias).
				Errorf("duplicate alias '%s'", alias)
		}
		seen[lower] = struct{}{}
	}

	return nil
}

func validationErr(msg string) error {
	return oops.
		Code(codeValidation).
		In("validation").
		Errorf("%s", msg)
}
```

**Step 4: Run tests**

Run: `go test ./internal/validation/ -v -count=1`
Expected: All tests pass.

**Step 5: Commit**

```text
feat(validation): add IP, hostname, and alias validation

Port validation logic from Rust with identical rules:
RFC 1035 hostname, IPv4/IPv6 via net.ParseIP, alias dedup,
max 50 aliases. Includes property-based tests via rapid.
```

---

## Phase 3: Storage Layer

### Task 6: Define storage interfaces

**Files:**

- Create: `internal/storage/storage.go`

**Step 1: Write storage interface**

File: `internal/storage/storage.go`

Port from Rust `traits.rs`. Go interfaces are implicit so no registration needed.

```go
package storage

import (
	"context"
	"time"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/oklog/ulid/v2"
)

// EventStore is the write side of the CQRS pattern.
// Stores immutable events with optimistic concurrency control.
type EventStore interface {
	// AppendEvent appends a single event with optimistic concurrency check.
	// expectedVersion is the version the caller last saw; empty string means "first event".
	AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion string) error

	// AppendEvents appends multiple events atomically for one aggregate.
	AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion string) error

	// LoadEvents returns all events for an aggregate, ordered by version ascending.
	LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error)

	// GetCurrentVersion returns the latest version for an aggregate, or empty string if none.
	GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (string, error)

	// CountEvents returns the event count for an aggregate.
	CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error)
}

// SnapshotStore manages point-in-time snapshots of the hosts file.
type SnapshotStore interface {
	SaveSnapshot(ctx context.Context, snapshot domain.Snapshot) error
	GetSnapshot(ctx context.Context, snapshotID string) (*domain.Snapshot, error)
	ListSnapshots(ctx context.Context, limit, offset *uint32) ([]domain.SnapshotMetadata, error)
	DeleteSnapshot(ctx context.Context, snapshotID string) error
	ApplyRetentionPolicy(ctx context.Context, maxCount *int, maxAgeDays *int) (int, error)
}

// HostProjection is the read side of the CQRS pattern.
// Provides optimized queries over current host entry state.
type HostProjection interface {
	ListAll(ctx context.Context) ([]domain.HostEntry, error)
	GetByID(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error)
	FindByIPAndHostname(ctx context.Context, ip, hostname string) (*domain.HostEntry, error)
	Search(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error)
	GetAtTime(ctx context.Context, at time.Time) ([]domain.HostEntry, error)
}

// Storage combines all storage interfaces with lifecycle management.
type Storage interface {
	EventStore
	SnapshotStore
	HostProjection
	Initialize(ctx context.Context) error
	HealthCheck(ctx context.Context) error
	Close() error
	BackendName() string
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/storage/`
Expected: No errors.

**Step 3: Commit**

```text
feat(storage): define storage interfaces for CQRS pattern

EventStore (write), HostProjection (read), SnapshotStore
(versioning), and combined Storage interface. Port of Rust
trait definitions with Go-idiomatic signatures.
```

---

### Task 7: SQLite storage implementation — schema and migrations

**Files:**

- Create: `internal/storage/sqlite/migrations/001_initial.sql`
- Create: `internal/storage/sqlite/sqlite.go`

**Step 1: Write SQL migration**

File: `internal/storage/sqlite/migrations/001_initial.sql`

```sql
-- Events table (append-only event store)
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_data TEXT NOT NULL,
    event_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate ON events(aggregate_id, event_version);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- Snapshots table
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger_type TEXT NOT NULL,
    name TEXT,
    event_log_position INTEGER
);

CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots(created_at);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (1, datetime('now'));
```

**Step 2: Write SQLite storage struct skeleton**

File: `internal/storage/sqlite/sqlite.go`

```go
package sqlite

import (
	"context"
	"embed"
	"fmt"
	"log/slog"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Storage implements storage.Storage backed by SQLite (pure Go, no CGo).
type Storage struct {
	pool *sqlitex.Pool
	log  *slog.Logger
}

// Compile-time check that Storage implements storage.Storage.
var _ storage.Storage = (*Storage)(nil)

// New creates a new SQLite storage. Use ":memory:" for in-memory databases.
func New(dbPath string, logger *slog.Logger) (*Storage, error) {
	pool, err := sqlitex.NewPool(dbPath, sqlitex.PoolOptions{
		PoolSize: 10,
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite pool: %w", err)
	}

	return &Storage{pool: pool, log: logger}, nil
}

func (s *Storage) BackendName() string { return "sqlite" }

func (s *Storage) Initialize(ctx context.Context) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	migrationSQL, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}

	if err := sqlitex.ExecuteScript(conn, string(migrationSQL), nil); err != nil {
		return fmt.Errorf("apply migration: %w", err)
	}

	return nil
}

func (s *Storage) HealthCheck(ctx context.Context) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	defer s.pool.Put(conn)

	return sqlitex.ExecuteTransient(conn, "SELECT 1", nil)
}

func (s *Storage) Close() error {
	return s.pool.Close()
}
```

Note: EventStore, SnapshotStore, and HostProjection methods will be added
in subsequent tasks. This establishes the struct and lifecycle methods.

**Step 3: Fetch dependencies**

Run: `go mod tidy`
Expected: zombiezen.com/go/sqlite added.

**Step 4: Verify it compiles**

Run: `go build ./internal/storage/sqlite/`
Expected: Compile error — missing interface methods. This is expected; we implement them next.

**Step 5: Commit (partial — lifecycle only)**

```text
feat(storage): add SQLite storage skeleton with schema migration

Pure Go SQLite via zombiezen.com/go/sqlite (modernc backend).
Embedded SQL migrations, connection pool, Initialize/HealthCheck/Close.
EventStore and projection methods follow in subsequent commits.
```

---

### Task 8: SQLite EventStore implementation

**Files:**

- Modify: `internal/storage/sqlite/sqlite.go` (add EventStore methods)
- Create: `internal/storage/sqlite/eventstore.go`

**Step 1: Write EventStore methods**

File: `internal/storage/sqlite/eventstore.go`

```go
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oklog/ulid/v2"
	"github.com/samber/oops"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

func (s *Storage) AppendEvent(ctx context.Context, aggregateID ulid.ULID, event domain.EventEnvelope, expectedVersion string) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer endFn(&err)

	// Check optimistic concurrency
	if err := s.checkVersion(conn, aggregateID, expectedVersion); err != nil {
		return err
	}

	return s.insertEvent(conn, event)
}

func (s *Storage) AppendEvents(ctx context.Context, aggregateID ulid.ULID, events []domain.EventEnvelope, expectedVersion string) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	endFn, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer endFn(&err)

	if err := s.checkVersion(conn, aggregateID, expectedVersion); err != nil {
		return err
	}

	for _, event := range events {
		if err := s.insertEvent(conn, event); err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]domain.EventEnvelope, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return nil, fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	var events []domain.EventEnvelope

	err = sqlitex.Execute(conn,
		`SELECT event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by
		 FROM events WHERE aggregate_id = ? ORDER BY event_version ASC`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				envelope, err := scanEventEnvelope(stmt)
				if err != nil {
					return err
				}
				events = append(events, envelope)
				return nil
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}

	return events, nil
}

func (s *Storage) GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (string, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return "", fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	var version string
	err = sqlitex.Execute(conn,
		`SELECT event_version FROM events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				version = stmt.ColumnText(0)
				return nil
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf("get version: %w", err)
	}

	return version, nil
}

func (s *Storage) CountEvents(ctx context.Context, aggregateID ulid.ULID) (int64, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return 0, fmt.Errorf("take connection: %w", err)
	}
	defer s.pool.Put(conn)

	var count int64
	err = sqlitex.Execute(conn,
		`SELECT COUNT(*) FROM events WHERE aggregate_id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				count = stmt.ColumnInt64(0)
				return nil
			},
		},
	)
	if err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}

	return count, nil
}

// checkVersion verifies optimistic concurrency.
func (s *Storage) checkVersion(conn *sqlite.Conn, aggregateID ulid.ULID, expectedVersion string) error {
	var currentVersion string
	err := sqlitex.Execute(conn,
		`SELECT event_version FROM events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1`,
		&sqlitex.ExecOptions{
			Args: []any{aggregateID.String()},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				currentVersion = stmt.ColumnText(0)
				return nil
			},
		},
	)
	if err != nil {
		return fmt.Errorf("check version: %w", err)
	}

	if currentVersion != expectedVersion {
		return oops.
			Code(domain.CodeVersionConflict).
			With("aggregate_id", aggregateID.String()).
			With("expected", expectedVersion).
			With("actual", currentVersion).
			Errorf("version conflict: expected %q, got %q", expectedVersion, currentVersion)
	}

	return nil
}

// insertEvent inserts a single event row.
func (s *Storage) insertEvent(conn *sqlite.Conn, env domain.EventEnvelope) error {
	eventData, err := json.Marshal(env.Event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	return sqlitex.Execute(conn,
		`INSERT INTO events (event_id, aggregate_id, event_type, event_data, event_version, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		&sqlitex.ExecOptions{
			Args: []any{
				env.EventID.String(),
				env.AggregateID.String(),
				string(env.Event.Type),
				string(eventData),
				env.Version,
				env.CreatedAt.Format("2006-01-02T15:04:05.000Z"),
				ptrToAny(env.CreatedBy),
			},
		},
	)
}

func scanEventEnvelope(stmt *sqlite.Stmt) (domain.EventEnvelope, error) {
	eventIDStr := stmt.ColumnText(0)
	aggIDStr := stmt.ColumnText(1)
	_ = stmt.ColumnText(2) // event_type (embedded in event_data)
	eventDataStr := stmt.ColumnText(3)
	version := stmt.ColumnText(4)
	createdAtStr := stmt.ColumnText(5)
	createdBy := columnTextPtr(stmt, 6)

	eventID, err := ulid.Parse(eventIDStr)
	if err != nil {
		return domain.EventEnvelope{}, fmt.Errorf("parse event_id: %w", err)
	}

	aggID, err := ulid.Parse(aggIDStr)
	if err != nil {
		return domain.EventEnvelope{}, fmt.Errorf("parse aggregate_id: %w", err)
	}

	var event domain.HostEvent
	if err := json.Unmarshal([]byte(eventDataStr), &event); err != nil {
		return domain.EventEnvelope{}, fmt.Errorf("unmarshal event: %w", err)
	}

	createdAt, err := parseTime(createdAtStr)
	if err != nil {
		return domain.EventEnvelope{}, fmt.Errorf("parse created_at: %w", err)
	}

	return domain.EventEnvelope{
		EventID:     eventID,
		AggregateID: aggID,
		Event:       event,
		Version:     version,
		CreatedAt:   createdAt,
		CreatedBy:   createdBy,
	}, nil
}

func ptrToAny(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func columnTextPtr(stmt *sqlite.Stmt, col int) *string {
	if stmt.ColumnType(col) == sqlite.TypeNull {
		return nil
	}
	s := stmt.ColumnText(col)
	return &s
}

func parseTime(s string) (t time.Time, err error) {
	// Try multiple formats for robustness
	for _, layout := range []string{
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		time.RFC3339Nano,
	} {
		if t, err = time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}
```

Note: add `"time"` to the import block.

**Step 2: Verify it compiles**

Run: `go build ./internal/storage/sqlite/`
Expected: Still fails — SnapshotStore and HostProjection not yet implemented.

**Step 3: Commit (WIP — event store portion)**

```text
feat(storage): implement SQLite EventStore methods

AppendEvent/AppendEvents with optimistic concurrency via version
check, LoadEvents, GetCurrentVersion, CountEvents. JSON event
serialization with ULID parsing.
```

---

### Task 9: SQLite SnapshotStore implementation

**Files:**

- Create: `internal/storage/sqlite/snapshots.go`

**Step 1: Implement SnapshotStore methods**

File: `internal/storage/sqlite/snapshots.go`

This file implements `SaveSnapshot`, `GetSnapshot`, `ListSnapshots`,
`DeleteSnapshot`, `ApplyRetentionPolicy` using the same `zombiezen` SQLite
pool pattern. Follows the same query/scan patterns as the EventStore.

Key SQL patterns:

- `INSERT INTO snapshots` for save
- `SELECT ... WHERE snapshot_id = ?` for get
- `SELECT ... ORDER BY created_at DESC LIMIT ? OFFSET ?` for list
- `DELETE FROM snapshots WHERE snapshot_id = ?` for delete
- Retention: `DELETE FROM snapshots WHERE snapshot_id IN (SELECT ... ORDER BY created_at DESC LIMIT -1 OFFSET ?)` for count-based, `DELETE FROM snapshots WHERE created_at < ?` for age-based

**Step 2: Commit**

```text
feat(storage): implement SQLite SnapshotStore methods

SaveSnapshot, GetSnapshot, ListSnapshots, DeleteSnapshot,
ApplyRetentionPolicy with count-based and age-based limits.
```

---

### Task 10: SQLite HostProjection implementation

**Files:**

- Create: `internal/storage/sqlite/projection.go`

**Step 1: Implement HostProjection methods**

File: `internal/storage/sqlite/projection.go`

The projection reads events and reconstructs current state. Key methods:

- `ListAll`: Load all aggregate IDs, replay events for each, return non-deleted entries
- `GetByID`: Load events for one aggregate, reconstruct
- `FindByIPAndHostname`: ListAll + filter (or optimize with a view later)
- `Search`: Apply filter patterns against reconstructed entries
- `GetAtTime`: Replay events up to timestamp

Helper function `replayEvents(events []EventEnvelope) *HostEntry` applies
events sequentially to build current state — this is the core of event
sourcing.

**Step 2: Verify full interface is satisfied**

Run: `go build ./internal/storage/sqlite/`
Expected: Compiles — all Storage interface methods implemented.

**Step 3: Commit**

```text
feat(storage): implement SQLite HostProjection with event replay

ListAll, GetByID, FindByIPAndHostname, Search, GetAtTime.
Core replayEvents function reconstructs HostEntry from event log.
```

---

### Task 11: Storage compliance test suite

**Files:**

- Create: `internal/storage/storage_test.go`

**Step 1: Write shared compliance tests**

File: `internal/storage/storage_test.go`

Test suite that validates any `Storage` implementation. Uses in-memory SQLite.
Port the 42 test cases from the Rust shared test suite. Key test categories:

1. **EventStore tests**: append, load, version conflict, count, ordering
2. **SnapshotStore tests**: save, get, list, delete, retention policy
3. **HostProjection tests**: list all, get by ID, find by IP+hostname, search, time travel
4. **Lifecycle tests**: initialize idempotent, health check, close

Use `testify/suite` for organized test grouping.

```go
package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

type StorageComplianceSuite struct {
	suite.Suite
	store storage.Storage
}

func (s *StorageComplianceSuite) SetupTest() {
	store, err := sqlite.New(":memory:", slog.Default())
	s.Require().NoError(err)
	s.Require().NoError(store.Initialize(context.Background()))
	s.store = store
}

func (s *StorageComplianceSuite) TearDownTest() {
	s.store.Close()
}

// ... 42+ test methods ...

func TestStorageCompliance(t *testing.T) {
	suite.Run(t, new(StorageComplianceSuite))
}
```

**Step 2: Run tests**

Run: `go test ./internal/storage/ -v -count=1`
Expected: All tests pass.

**Step 3: Commit**

```text
test(storage): add compliance test suite for Storage interface

42+ tests covering EventStore, SnapshotStore, HostProjection
lifecycle. Validates in-memory SQLite implementation. Any future
backend must pass this same suite.
```

---

## Phase 4: Server Core

### Task 12: Server configuration

**Files:**

- Create: `internal/config/server.go`
- Create: `internal/config/server_test.go`

**Step 1: Write server config struct and TOML parsing**

Port from Rust server config. Same TOML structure for compatibility.

Key sections: `[server]`, `[database]`, `[tls]`, `[retention]`, `[hooks]`,
`[tls.acme]`, `[metrics]`.

**Step 2: Write tests for config loading**

Test: default values, TOML parsing, env var override, missing required fields.

**Step 3: Commit**

```text
feat(config): add server configuration with TOML parsing

Server, database, TLS, retention, hooks, ACME, and metrics
sections. Compatible with existing Rust config file format.
```

---

### Task 13: Client configuration

**Files:**

- Create: `internal/config/client.go`
- Create: `internal/config/client_test.go`

**Step 1: Write client config with precedence**

CLI args > env vars > config file. Same env vars: `ROUTER_HOSTS_SERVER`,
`ROUTER_HOSTS_CERT`, `ROUTER_HOSTS_KEY`, `ROUTER_HOSTS_CA`.

**Step 2: Commit**

```text
feat(config): add client configuration with precedence

CLI args > env vars > config file. XDG-compliant default path
at ~/.config/router-hosts/client.toml.
```

---

### Task 14: gRPC server with mTLS

**Files:**

- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

**Step 1: Implement gRPC server setup**

- `crypto/tls` mTLS with `tls.RequireAndVerifyClientCert`
- Graceful shutdown on SIGTERM/SIGINT (30s drain)
- SIGHUP cert reload via `tls.Config.GetCertificate`
- Wire `HostsService` gRPC service

**Step 2: Test with bufconn**

Use `google.golang.org/grpc/test/bufconn` for in-process testing without
real network.

**Step 3: Commit**

```text
feat(server): add gRPC server with mTLS and graceful shutdown

crypto/tls mTLS, SIGHUP cert reload, SIGTERM graceful shutdown
with 30-second drain. Tested with bufconn.
```

---

### Task 15: Command handler (domain logic)

**Files:**

- Create: `internal/server/commands.go`
- Create: `internal/server/commands_test.go`

**Step 1: Implement command handler**

Business logic for host operations: AddHost, UpdateHost, DeleteHost.
Validates input, checks for duplicates, creates events, appends to store.
This is the bridge between gRPC service and storage.

**Step 2: Test with mock storage**

Unit test command handler with an in-memory storage implementation.

**Step 3: Commit**

```text
feat(server): add command handler for host operations

AddHost, UpdateHost, DeleteHost with validation, duplicate
detection, event creation, and optimistic concurrency.
```

---

### Task 16: gRPC service implementation (CRUD)

**Files:**

- Create: `internal/server/service.go`
- Create: `internal/server/service_test.go`

**Step 1: Implement HostsService gRPC methods**

Wire AddHost, GetHost, UpdateHost, DeleteHost, ListHosts, SearchHosts.
Map domain errors (oops codes) to gRPC status codes.

**Step 2: Test with bufconn**

End-to-end gRPC tests: client → bufconn → service → storage.

**Step 3: Commit**

```text
feat(server): implement gRPC HostsService CRUD methods

AddHost, GetHost, UpdateHost, DeleteHost, ListHosts, SearchHosts.
Error code mapping from oops to gRPC status codes.
```

---

### Task 17: Hosts file generation

**Files:**

- Create: `internal/server/hostsfile.go`
- Create: `internal/server/hostsfile_test.go`

**Step 1: Implement atomic hosts file writer**

Same algorithm as Rust: generate content → write to .tmp → fsync → rename.
Sorted by IP then hostname, aliases on same line, comments inline, tags
in brackets.

**Step 2: Test output format and atomic write**

Test against known input → expected hosts file content. Use temp directories.

**Step 3: Commit**

```text
feat(server): add atomic hosts file generation

Write to .tmp, fsync, rename pattern. Sorted output per hosts(5)
with aliases, inline comments, and tag brackets.
```

---

### Task 18: Post-edit hooks

**Files:**

- Create: `internal/server/hooks.go`
- Create: `internal/server/hooks_test.go`

**Step 1: Implement hook runner**

`os/exec.CommandContext` with configurable timeout. Environment variables:
`ROUTER_HOSTS_EVENT`, `ROUTER_HOSTS_ENTRY_COUNT`, `ROUTER_HOSTS_ERROR`.

**Step 2: Test hook execution and timeout**

**Step 3: Commit**

```text
feat(server): add post-edit hook execution

Sequential hook runner with configurable timeout, structured
environment variables. Failures logged, don't fail the operation.
```

---

### Task 19: Write queue

**Files:**

- Create: `internal/server/writequeue.go`
- Create: `internal/server/writequeue_test.go`

**Step 1: Implement channel-based write serialization**

Single goroutine processing write commands from buffered channel.
Response delivered via per-request result channel.

**Step 2: Test concurrent write ordering**

**Step 3: Commit**

```text
feat(server): add channel-based write queue

Serializes concurrent writes to prevent race conditions.
Single goroutine processes commands, maintains event ordering.
```

---

## Phase 5: Streaming RPCs & Advanced Server

### Task 20: Import/Export streaming RPCs

**Files:**

- Modify: `internal/server/service.go` (add ImportHosts, ExportHosts)

**Step 1: Implement ImportHosts (bidi streaming)**

Chunked upload, conflict modes (skip/replace/strict), validation with
line errors, progress responses.

**Step 2: Implement ExportHosts (server streaming)**

Stream current state in hosts/json/csv format.

**Step 3: Commit**

```text
feat(server): implement Import/Export streaming RPCs

ImportHosts with conflict modes and progress tracking.
ExportHosts in hosts, JSON, and CSV formats.
```

---

### Task 21: Snapshot RPCs

**Files:**

- Modify: `internal/server/service.go` (add snapshot methods)

**Step 1: Implement CreateSnapshot, ListSnapshots, RollbackToSnapshot, DeleteSnapshot**

Rollback creates pre-snapshot for undo capability.

**Step 2: Commit**

```text
feat(server): implement snapshot gRPC methods

CreateSnapshot, ListSnapshots, RollbackToSnapshot (with backup
snapshot), DeleteSnapshot. Retention policy on creation.
```

---

### Task 22: Health check RPCs

**Files:**

- Modify: `internal/server/service.go` (add Liveness, Readiness, Health)

**Step 1: Implement health checks**

Liveness: always true. Readiness: storage health check. Health: detailed
status of all components.

**Step 2: Commit**

```text
feat(server): implement health check RPCs

Liveness (always alive), Readiness (storage connectivity),
Health (detailed component status).
```

---

## Phase 6: Client CLI

### Task 23: Cobra CLI scaffold with root command

**Files:**

- Modify: `cmd/router-hosts/main.go`
- Create: `internal/client/commands/root.go`

**Step 1: Set up Cobra with global flags**

`--server`, `--cert`, `--key`, `--ca`, `--config`, `--format`, `--quiet`,
`--verbose`. Add `server` subcommand and `host`/`snapshot`/`config` groups.

**Step 2: Commit**

```text
feat(client): scaffold Cobra CLI with global flags

Root command with server, host, snapshot, config subcommand
groups. Global TLS, output format, and verbosity flags.
```

---

### Task 24: gRPC client wrapper

**Files:**

- Create: `internal/client/client.go`

**Step 1: Implement gRPC client with mTLS**

Connection setup, dial options, interceptors for logging.

**Step 2: Commit**

```text
feat(client): add gRPC client wrapper with mTLS

Connection setup from config, TLS certificate loading,
and dial options.
```

---

### Task 25: Host CRUD CLI commands

**Files:**

- Create: `internal/client/commands/host.go`

**Step 1: Implement host add, get, update, delete, list, search commands**

Each command: parse flags → create gRPC request → call service → format output.

**Step 2: Commit**

```text
feat(client): implement host CRUD CLI commands

add, get, update, delete, list, search with flag parsing
and gRPC calls.
```

---

### Task 26: Output formatting with Lip Gloss

**Files:**

- Create: `internal/client/output/table.go`
- Create: `internal/client/output/json.go`
- Create: `internal/client/output/csv.go`

**Step 1: Implement formatters**

Table (Lip Gloss styled + bubbles/table), JSON, CSV. Selected by `--format`
flag. Non-TTY detection for pipe-friendly output.

**Step 2: Commit**

```text
feat(client): add output formatters (table, JSON, CSV)

Lip Gloss styled table output with bubbles/table component.
JSON and CSV for scripting. Auto-detect TTY for raw output.
```

---

### Task 27: Snapshot and import/export CLI commands

**Files:**

- Create: `internal/client/commands/snapshot.go`
- Create: `internal/client/commands/importexport.go`

**Step 1: Implement remaining CLI commands**

Snapshot create/list/rollback/delete, host import/export.

**Step 2: Commit**

```text
feat(client): implement snapshot and import/export CLI commands

snapshot create, list, rollback, delete. host import with
conflict modes, host export with format selection.
```

---

### Task 28: Bubble Tea interactive features

**Files:**

- Create: `internal/client/tui/conflict.go`
- Create: `internal/client/tui/progress.go`

**Step 1: Implement conflict resolution TUI**

Bubble Tea model for version conflict: show diff, prompt to retry with
current version.

**Step 2: Implement import progress bar**

Bubble Tea model with progress bar, entry counts, validation error display.

**Step 3: Commit**

```text
feat(client): add Bubble Tea interactive TUI components

Version conflict resolution with diff display. Import progress
bar with streaming counters and validation error display.
```

---

## Phase 7: OpenTelemetry Metrics

### Task 29: Metrics instrumentation

**Files:**

- Create: `internal/server/metrics.go`
- Create: `internal/server/metrics_test.go`

**Step 1: Implement OTel metrics**

Same metric names as Rust for Grafana compatibility. gRPC interceptors
for request metrics. Storage wrapper for operation metrics.

**Step 2: Commit**

```text
feat(server): add OpenTelemetry metrics instrumentation

Same metric names as Rust version for dashboard compatibility.
gRPC interceptors for request/duration metrics. Storage operation
counters and histograms.
```

---

## Phase 8: ACME Certificate Management

### Task 30: lego ACME wrapper

**Files:**

- Create: `internal/acme/acme.go`
- Create: `internal/acme/acme_test.go`

**Step 1: Implement lego wrapper**

DNS-01 challenge with Cloudflare provider. Background renewal goroutine.
Hot-swap via `tls.Config.GetCertificate` callback.

**Step 2: Commit**

```text
feat(acme): add lego wrapper for DNS-01/Cloudflare

Automatic certificate acquisition and renewal. Background
goroutine checks expiry, hot-swaps via GetCertificate callback.
```

---

## Phase 9: Kubernetes Operator

### Task 31: kubebuilder scaffold

**Files:**

- Create: `operator/` directory structure via kubebuilder
- Create: `cmd/operator/main.go`

**Step 1: Initialize kubebuilder project**

Run: `kubebuilder init --domain fzymgc.house --repo github.com/fzymgc-house/router-hosts`

**Step 2: Create HostMapping CRD**

Run: `kubebuilder create api --group router-hosts --version v1alpha1 --kind HostMapping`

**Step 3: Commit**

```text
feat(operator): scaffold kubebuilder project with HostMapping CRD

Initialize operator with controller-runtime. HostMapping CRD
for manual DNS entry registration.
```

---

### Task 32: HostMapping reconciler

**Files:**

- Modify: `operator/controllers/hostmapping_controller.go`

**Step 1: Implement reconciler**

Watch HostMapping CRDs, sync host entries with router-hosts server via
gRPC client. Handle create, update, delete.

**Step 2: Commit**

```text
feat(operator): implement HostMapping reconciler

Syncs HostMapping CRD state with router-hosts server via gRPC.
Handles create, update, delete with status conditions.
```

---

### Task 33: IngressRoute reconciler

**Files:**

- Create: `operator/controllers/ingressroute_controller.go`

**Step 1: Implement Traefik IngressRoute watcher**

Watch IngressRoute and IngressRouteTCP CRDs, extract host rules,
register with router-hosts server.

**Step 2: Commit**

```text
feat(operator): add IngressRoute reconciler for Traefik

Watches IngressRoute and IngressRouteTCP CRDs, extracts host
rules, and syncs DNS entries with router-hosts server.
```

---

## Phase 10: CI/CD & Packaging

### Task 34: Dockerfile

**Files:**

- Create: `Dockerfile.go` (temporary, will replace `Dockerfile`)

**Step 1: Write multi-stage Dockerfile**

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o router-hosts ./cmd/router-hosts

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /build/router-hosts /usr/local/bin/
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/router-hosts"]
CMD ["server", "--config", "/etc/router-hosts/server.toml"]
```

**Step 2: Commit**

```text
build: add Go multi-stage Dockerfile with distroless base

CGO_ENABLED=0 for static binary, distroless nonroot base image.
```

---

### Task 35: GoReleaser configuration

**Files:**

- Create: `.goreleaser.yml`

**Step 1: Configure GoReleaser**

Two binaries: `router-hosts` and `operator`. Cross-compile for
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

**Step 2: Commit**

```text
build: add GoReleaser configuration for releases

Cross-compilation for linux and darwin (amd64/arm64).
Two binaries: router-hosts and operator.
```

---

### Task 36: GitHub Actions CI workflow

**Files:**

- Create: `.github/workflows/ci-go.yml`

**Step 1: Write CI workflow**

Matrix: ubuntu-24.04 + macOS. Steps: checkout, setup-go, buf generate,
lint, test with coverage, build.

**Step 2: Commit**

```text
ci: add GitHub Actions workflow for Go CI

Lint (golangci-lint), test with coverage (80% threshold),
build, and proto validation.
```

---

### Task 37: Wire main.go entry point

**Files:**

- Modify: `cmd/router-hosts/main.go`

**Step 1: Wire everything together**

Server mode: load config → init storage → start gRPC server.
Client mode: parse CLI → connect gRPC → execute command.

**Step 2: Verify build and basic smoke test**

Run: `go build ./cmd/router-hosts && ./router-hosts --help`
Expected: CLI help output with all commands.

**Step 3: Commit**

```text
feat: wire main entry point for server and client modes

Server mode initializes storage, starts gRPC with mTLS.
Client mode parses CLI and connects via gRPC.
```

---

## Phase 11: E2E Tests

### Task 38: Docker-based E2E test harness

**Files:**

- Create: `e2e/e2e_test.go`
- Create: `e2e/helpers.go`

**Step 1: Write E2E test framework**

Docker container with real mTLS. Self-signed cert generation. Server
healthcheck probes. Port the 10 existing Rust E2E scenarios.

**Step 2: Commit**

```text
test(e2e): add Docker-based E2E tests with real mTLS

Self-signed cert generation, container lifecycle management,
health check probes. Covers CRUD, auth, disaster recovery.
```

---

## Phase 12: Cleanup & Archival

### Task 39: Archive Rust codebase

**Files:**

- Remove: `crates/`, `Cargo.toml`, `Cargo.lock` (on separate branch)
- Rename: `Taskfile.go.yml` → `Taskfile.yml`
- Rename: `Dockerfile.go` → `Dockerfile`
- Update: `CLAUDE.md` for Go conventions
- Update: `lefthook.yaml` for Go hooks

**Step 1: Create archival tag for Rust version**

```bash
git tag v0.8.14-rust-final
```

**Step 2: Remove Rust files and replace with Go equivalents**

**Step 3: Update CLAUDE.md**

Replace Rust-specific instructions with Go equivalents:

- `task` commands stay (just different underlying tools)
- `cargo clippy` → `golangci-lint`
- `cargo fmt` → `gofumpt`
- `cargo test` → `go test`
- Error handling: `Result<T,E>` → `error` return
- Coverage: same 80% threshold

**Step 4: Update lefthook hooks**

Replace cargo-fmt, clippy with gofumpt, golangci-lint.

**Step 5: Commit**

```text
chore: archive Rust codebase and activate Go implementation

Tag v0.8.14-rust-final for archival. Remove Rust crates, replace
with Go source. Update CLAUDE.md, Taskfile, lefthook for Go.
```

---

## Dependency Graph

```text
Phase 0 (Scaffold)
  └── Task 1: Go module + dirs
  └── Task 2: Taskfile
  └── Task 3: buf codegen

Phase 1 (Domain) ← depends on Phase 0
  └── Task 4: Events, types, errors

Phase 2 (Validation) ← depends on Phase 0
  └── Task 5: IP, hostname, alias validation

Phase 3 (Storage) ← depends on Phase 1
  └── Task 6: Storage interface
  └── Task 7: SQLite skeleton + migrations  ← depends on Task 6
  └── Task 8: EventStore impl              ← depends on Task 7
  └── Task 9: SnapshotStore impl           ← depends on Task 7
  └── Task 10: HostProjection impl          ← depends on Task 8
  └── Task 11: Compliance test suite        ← depends on Tasks 8-10

Phase 4 (Server Core) ← depends on Phase 3
  └── Task 12: Server config
  └── Task 13: Client config
  └── Task 14: gRPC server + mTLS           ← depends on Task 12
  └── Task 15: Command handler              ← depends on Tasks 6, 5
  └── Task 16: gRPC service (CRUD)          ← depends on Tasks 14, 15
  └── Task 17: Hosts file generation
  └── Task 18: Post-edit hooks
  └── Task 19: Write queue

Phase 5 (Streaming) ← depends on Phase 4
  └── Task 20: Import/Export RPCs
  └── Task 21: Snapshot RPCs
  └── Task 22: Health check RPCs

Phase 6 (Client) ← depends on Phase 4
  └── Task 23: Cobra CLI scaffold
  └── Task 24: gRPC client wrapper
  └── Task 25: Host CRUD commands           ← depends on Tasks 23, 24
  └── Task 26: Output formatting
  └── Task 27: Snapshot + import/export CLI ← depends on Task 25
  └── Task 28: Bubble Tea TUI

Phase 7 (Metrics) ← depends on Phase 4
  └── Task 29: OTel instrumentation

Phase 8 (ACME) ← depends on Phase 4
  └── Task 30: lego ACME wrapper

Phase 9 (Operator) ← depends on Phase 4
  └── Task 31: kubebuilder scaffold
  └── Task 32: HostMapping reconciler       ← depends on Task 31
  └── Task 33: IngressRoute reconciler      ← depends on Task 31

Phase 10 (CI/CD) ← depends on Phases 6-9
  └── Task 34: Dockerfile
  └── Task 35: GoReleaser
  └── Task 36: GitHub Actions
  └── Task 37: Wire main.go

Phase 11 (E2E) ← depends on Phase 10
  └── Task 38: E2E tests

Phase 12 (Cleanup) ← depends on Phase 11
  └── Task 39: Archive Rust, activate Go
```

## Parallelization Opportunities

These task groups can be worked on concurrently by independent agents:

- **Group A**: Tasks 4-5 (domain + validation) — no shared dependencies
- **Group B**: Tasks 12-13 (server + client config) — independent of each other
- **Group C**: Tasks 17-19 (hosts file, hooks, write queue) — independent server utilities
- **Group D**: Tasks 25-28 (CLI commands + TUI) — can proceed in parallel once Task 24 is done
- **Group E**: Tasks 29-30 (metrics + ACME) — independent of each other
- **Group F**: Tasks 31-33 (operator) — independent of client CLI work
- **Group G**: Tasks 34-36 (CI/CD) — independent of each other
