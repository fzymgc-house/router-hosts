---
schema_version: 1
open_count: 1
waived_count: 0
fixed_count: 0
total_count: 1
last_updated: 2026-08-01T19:45:10.272Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | internal/client/commands/watch_test.go |  | 01-07: TestWatchPolicy_StatusIntervalDefaultsFromPolicy/_ExplicitStatusIntervalFlagOverridesPolicy moved from watchpolicy_test.go (Task 1) to watch_test.go (Task 2) as TestWatch_*, since they exercise newWatchCmd's own flag registration which does not exist until Task 2 lands. | open |  | 2026-08-01T19:45:10.272Z |  |

````json
[
  {
    "id": 1,
    "kind": "deviation",
    "phase": "01",
    "file": "internal/client/commands/watch_test.go",
    "line": null,
    "description": "01-07: TestWatchPolicy_StatusIntervalDefaultsFromPolicy/_ExplicitStatusIntervalFlagOverridesPolicy moved from watchpolicy_test.go (Task 1) to watch_test.go (Task 2) as TestWatch_*, since they exercise newWatchCmd's own flag registration which does not exist until Task 2 lands.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-01T19:45:10.272Z",
    "resolved_at": null
  }
]
````
