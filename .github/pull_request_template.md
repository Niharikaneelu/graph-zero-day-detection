## Summary

Describe what this PR changes and why.

## Scope

- [ ] Simulation
- [ ] Detection
- [ ] Containment
- [ ] Dashboard
- [ ] Docs
- [ ] Other

## Data Contract Impact

- [ ] No interface changes
- [x] Interface changed: containment now returns canonical `cut_edges` while
	retaining `recommended_edges` as a compatibility alias; simulator updates
	add missing node `type` metadata without overwriting existing values.

If changed, explain the impact on:

- Event format
- Detection output
- Containment output: `cut_edges` is canonical and equals the legacy alias
	`recommended_edges`.

## Validation

- [ ] Local tests passed
- [ ] CI passed
- [ ] Manual check done (if needed)

Commands run:

```text
paste commands and results here
```

## Risk and Rollback

Risk level:

- [ ] Low
- [ ] Medium
- [ ] High

Rollback plan:

Describe how to safely revert if needed.

## Checklist

- [ ] Single-purpose PR
- [ ] No unnecessary dependencies
- [ ] Updated docs if behavior changed
- [ ] Requested review from path owner(s)
