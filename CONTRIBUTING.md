# Contributing to router-hosts

Thanks for your interest in contributing.

This project is developed with the [GSD](https://github.com/open-gsd/gsd-core)
workflow. Phase status and requirements live in `.planning/`; contribution
process lives here.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are to be
interpreted as described in RFC 2119.

## The issue-first rule

**Every pull request MUST link an issue that was opened and accepted first.**

Opening a PR without a linked, approved issue wastes your time and ours: scope
gets settled in review instead of before implementation, and the PR usually
needs rewriting. PRs that do not satisfy the gates below are closed unmerged —
you are welcome to reopen once the issue is approved.

### Approval gates

| Change type | Issue template | Required label before a PR is merged | Who applies it |
|---|---|---|---|
| New functionality | [Feature request](.github/ISSUE_TEMPLATE/feature_request.yml) | `approved-feature` | Maintainer |
| Improving existing behavior | [Enhancement](.github/ISSUE_TEMPLATE/enhancement.yml) | `approved-enhancement` | Maintainer |
| Something is broken | [Bug report](.github/ISSUE_TEMPLATE/bug_report.yml) | `confirmed-bug` | Maintainer |
| Internal maintenance | [Chore](.github/ISSUE_TEMPLATE/chore.yml) | none (triage only) | — |

New issues land with `needs-review` (features, enhancements) or `needs-triage`
(bugs, chores). A maintainer replaces that with the approval label once scope
and root cause are agreed.

**Features and enhancements:** wait for the approval label *before* writing
code. **Bugs:** you MAY start immediately, but the fix will not merge until the
issue carries `confirmed-bug`, so that we agree on the root cause and not just
the symptom.

## Choosing the right template

Picking the wrong template is the most common reason an issue stalls.

- Does the behavior exist today and work as designed, but poorly? → **Enhancement**
- Does the behavior not exist at all? → **Feature request**
- Does the behavior exist and is demonstrably wrong? → **Bug report**
- Is there no user-visible change whatsoever? → **Chore**

## Pull requests

### Pick a PR template explicitly

GitHub does **not** offer a template picker for this repository — the typed
templates live in a directory and must be selected via a URL parameter. Append
one of these to your compare URL:

- Feature: `?expand=1&template=feature.md`
- Enhancement: `?expand=1&template=enhancement.md`
- Fix: `?expand=1&template=fix.md`

For example:

```text
https://github.com/fzymgc-house/router-hosts/compare/main...my-branch?expand=1&template=fix.md
```

Or with the CLI, filling the body from the template file:

```bash
gh pr create --repo fzymgc-house/router-hosts --base main --head my-branch \
  --body-file .github/PULL_REQUEST_TEMPLATE/fix.md
```

A PR that uses the default empty body is flagged as **Wrong Template** during
triage and sent back.

### PR requirements

- PRs MUST link their issue in the body: `Closes #123` (feature/enhancement) or
  `Fixes #123` (bug)
- PRs MUST pass all CI checks before merge
- PRs SHOULD stay under 400 lines changed — split larger work into stacked PRs
- PRs MUST address one concern; do not mix a fix with an enhancement
- PRs MUST NOT contain unrelated formatting churn

### Branching

Branch from `main`. Do not push to `main` directly.

```bash
git switch -c feat/my-feature main
```

Prefixes: `feat/`, `fix/`, `refactor/`, `docs/`.

For isolated work, use a worktree and install hooks in it:

```bash
git worktree add ../rh-my-feature -b feat/my-feature
cd ../rh-my-feature && lefthook install
```

### Commits

[Conventional Commits](https://www.conventionalcommits.org/) are enforced by
cocogitto via lefthook, and release-please derives the changelog and version
bump from them — so the type you choose determines the release.

```text
<type>(<scope>): <subject>

<body>

<footer>
```

- **Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`
- **Scopes:** `proto`, `server`, `client`, `storage`, `validation`, `config`, `ci`, `deps`, `docs`, `operator`, `acme`, `e2e`
- Subject MUST be <= 50 characters, imperative mood, no trailing period
- Body SHOULD wrap at 72 characters
- Footer MUST reference the issue: `Fixes #123` / `Closes #456`

One logical change per commit.

## Development setup

Prerequisites:

- **Go** 1.25+ — `brew install go`
- **buf** — `brew install bufbuild/buf/buf`
- **cocogitto** — `brew install cocogitto`
- **lefthook** — `brew install lefthook && lefthook install`
- **golangci-lint** — `brew install golangci-lint`
- **gofumpt** — `go install mvdan.cc/gofumpt@latest`
- **Task** — `brew install go-task`

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
lefthook install
task build
task test
```

Use `task` rather than invoking `go` directly. Run `task --list` for the full
set; the ones you need most:

| Command | Purpose |
|---------|---------|
| `task build` | Build all binaries |
| `task test` | Run all tests with the race detector |
| `task test:coverage:ci` | Coverage with the 80% threshold |
| `task lint` | golangci-lint + buf lint |
| `task fmt` | gofumpt + buf format |
| `task proto:generate` | Regenerate protobuf Go stubs |
| `task ci` | Run the full CI pipeline locally |

## Code quality bar

- Fallible functions MUST return `error`, wrapped with `samber/oops` and
  context: `oops.Wrapf(err, "doing X")`
- Library code MUST NOT call `log.Fatal` or `os.Exit`
- All new code MUST have tests; every bug fix MUST have a regression test that
  fails before the fix
- Tests MUST NOT write to the real filesystem — use `t.TempDir()`
- Total coverage MUST stay at or above 80%
- `//nolint` directives MUST NOT be added without written justification and
  maintainer approval — fix the warning instead of suppressing it

## Security

Do not open a public issue for security vulnerabilities. Report them privately
via [GitHub Security Advisories](https://github.com/fzymgc-house/router-hosts/security/advisories/new).

## Further reading

| Topic | Location |
|-------|----------|
| Architecture and design | [docs/contributing/architecture.md](docs/contributing/architecture.md) |
| Testing strategy | [docs/contributing/testing.md](docs/contributing/testing.md) |
| Release process | [docs/contributing/releasing.md](docs/contributing/releasing.md) |
| Roadmap and phase status | [.planning/ROADMAP.md](.planning/ROADMAP.md) |
