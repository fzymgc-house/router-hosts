package ciwiring_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflowPath is relative to this package's directory.
const workflowPath = "../../.github/workflows/ci-go.yml"

const aggregatorJobID = "ci-go-complete"

// gatedTierJobPattern matches every job-id prefix this invariant treats as a
// "gated tier" — a job whose result must be folded into ci-go-complete's
// needs list. Today that is the e2e-* tiers (Phase 1, T-01-01) and the
// bench-* tier (Phase 2's LAZY-02 benchmark gate, T-02-21). Extending this
// alternation is how a future gated tier joins the invariant.
var gatedTierJobPattern = regexp.MustCompile(`^(?:e2e|bench)-`)

type workflowStep struct {
	Env map[string]string `yaml:"env"`
	Run string            `yaml:"run"`
}

type workflowJob struct {
	Name  string         `yaml:"name"`
	If    string         `yaml:"if"`
	Needs []string       `yaml:"needs"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowFile struct {
	On   map[string]any         `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

// loadWorkflow reads and parses the CI workflow file. It fails the test
// outright (never skips) if the file is missing or unparseable, because a
// missing workflow file is exactly the kind of silent gap this invariant
// exists to catch.
func loadWorkflow(t *testing.T) workflowFile {
	t.Helper()

	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowPath, err)
	}

	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing %s: %v", workflowPath, err)
	}
	return wf
}

// gatedTierJobIDs returns the sorted set of top-level job ids matching
// gatedTierJobPattern.
func gatedTierJobIDs(jobs map[string]workflowJob) []string {
	var ids []string
	for id := range jobs {
		if gatedTierJobPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// gatedTierNeedsIDs returns the sorted set of ids inside a needs: list
// matching gatedTierJobPattern.
func gatedTierNeedsIDs(needs []string) []string {
	var ids []string
	for _, id := range needs {
		if gatedTierJobPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// setDiff reports elements present in a but not b, and in b but not a.
func setDiff(a, b []string) (onlyInA, onlyInB []string) {
	inB := make(map[string]bool)
	for _, id := range b {
		inB[id] = true
	}
	inA := make(map[string]bool)
	for _, id := range a {
		inA[id] = true
	}
	for _, id := range a {
		if !inB[id] {
			onlyInA = append(onlyInA, id)
		}
	}
	for _, id := range b {
		if !inA[id] {
			onlyInB = append(onlyInB, id)
		}
	}
	return onlyInA, onlyInB
}

// resultEnvBinding finds the env var in job's steps whose value is exactly
// "${{ needs.<tierID>.result }}", returning its name and how many such
// bindings were found (the caller asserts this is exactly one).
func resultEnvBinding(job workflowJob, tierID string) (name string, count int) {
	want := "${{ needs." + tierID + ".result }}"
	for _, step := range job.Steps {
		for envName, value := range step.Env {
			if value == want {
				name = envName
				count++
			}
		}
	}
	return name, count
}

// aggregatorRunScript joins every step's run: script in job, in step order.
func aggregatorRunScript(job workflowJob) string {
	var scripts []string
	for _, step := range job.Steps {
		if step.Run != "" {
			scripts = append(scripts, step.Run)
		}
	}
	return strings.Join(scripts, "\n")
}

// TestEveryGatedTierIsWiredIntoAggregator is the phase's standing structural
// invariant (T-01-01, extended by T-02-21 to cover the bench-* tier): the
// set of top-level gated-tier jobs (e2e-* and bench-*) must equal the set of
// such jobs represented in ci-go-complete's needs list, each with its own
// distinct *_RESULT env binding compared against "success" with !=. Adding a
// new gated-tier job without wiring it into all three locations turns this
// red with no edit to this test required.
func TestEveryGatedTierIsWiredIntoAggregator(t *testing.T) {
	wf := loadWorkflow(t)

	aggregator, ok := wf.Jobs[aggregatorJobID]
	if !ok {
		t.Fatalf("workflow has no %q job", aggregatorJobID)
	}

	// Guard against a tier drifting off the naming convention entirely,
	// which would make it invisible to both gatedTierJobIDs and
	// gatedTierNeedsIDs at once (both filter through the same
	// gatedTierJobPattern) and defeat this whole invariant. Must run before
	// the set-equality comparison below so an off-convention job fails with
	// this naming message rather than silently vanishing from both sides of
	// that comparison.
	for id := range wf.Jobs {
		lower := strings.ToLower(id)
		if (strings.Contains(lower, "e2e") || strings.Contains(lower, "bench")) && !gatedTierJobPattern.MatchString(id) {
			t.Fatalf("job %q looks like a gated tier but does not match the required e2e-*/bench-* naming convention this invariant depends on", id)
		}
	}

	declaredTiers := gatedTierJobIDs(wf.Jobs)
	wiredTiers := gatedTierNeedsIDs(aggregator.Needs)

	// Set equality via sorted-joined-string comparison carries both "no
	// fewer" and "no more" in a single check — never a length comparison,
	// which cannot distinguish "wrong members, same count" from "in sync".
	if strings.Join(declaredTiers, ",") != strings.Join(wiredTiers, ",") {
		onlyDeclared, onlyWired := setDiff(declaredTiers, wiredTiers)
		t.Fatalf(
			"gated-tier jobs and %s.needs are out of sync: declared but not needed=%v, needed but not declared=%v",
			aggregatorJobID, onlyDeclared, onlyWired,
		)
	}

	if declaredTiers == nil {
		t.Fatalf("expected at least one gated-tier job in the workflow, found none")
	}

	runScript := aggregatorRunScript(aggregator)

	for _, tierID := range declaredTiers {
		envVarName, count := resultEnvBinding(aggregator, tierID)
		if count == 0 {
			t.Fatalf("%s has no env var bound to ${{ needs.%s.result }}", aggregatorJobID, tierID)
		}
		if count != 1 {
			t.Fatalf("expected exactly one env var bound to ${{ needs.%s.result }} in %s, found %d (last seen: %s)", tierID, aggregatorJobID, count, envVarName)
		}

		wantComparison := `"$` + envVarName + `" != "success"`
		if !strings.Contains(runScript, wantComparison) {
			t.Fatalf("%s's run script does not compare %s against \"success\" with !=; expected to find %q", aggregatorJobID, envVarName, wantComparison)
		}
	}

	if strings.Contains(runScript, `== "failure"`) {
		t.Fatalf(`%s's run script must not use == "failure" comparisons (use != "success" so cancelled/skipped jobs also trip the gate)`, aggregatorJobID)
	}

	if aggregator.If != "always()" {
		t.Fatalf("%s must declare if: always(), got %q", aggregatorJobID, aggregator.If)
	}

	if aggregator.Name != "CI (Go) Complete" {
		t.Fatalf(`%s's name must remain "CI (Go) Complete" (it is the protect-main required-check context), got %q`, aggregatorJobID, aggregator.Name)
	}

	if _, ok := wf.On["workflow_dispatch"]; !ok {
		t.Fatalf("workflow's on: mapping must declare workflow_dispatch")
	}
}
