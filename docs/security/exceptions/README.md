# Security exceptions

A security exception is a dated, owned, time-boxed relaxation of a control that this repository keeps for
a reason. It is written down before the relaxation ships, expires on its own, and is reverted by an input
flip or a one-line change.

| ID | Control relaxed | Status | Expires |
|---|---|---|---|
| [EX-0001](EX-0001-harden-runner-block-westus2.md) | harden-runner `block` to `audit` for secretless jobs (westus2 runner DNS defect) | active | 2026-11-07 |

## Rules

- One file per exception, named `EX-NNNN-short-slug.md`. Numbers are never reused.
- An exception covers a named scope (workflow and job), never "all jobs".
- Secret-bearing jobs are never in scope. A job that is unclear stays under the control.
- The expiry is a date and, where there is one, the upstream event that ends it. An expired exception is
  reverted or renewed by a new dated entry; it is never left to lapse silently.
- A test or a check must hold the scope to what the file says, so the record cannot drift from the YAML.

## Template

```markdown
# EX-NNNN: <control> relaxed for <scope>

| Field | Value |
|---|---|
| ID | EX-NNNN |
| Date | YYYY-MM-DD |
| Owner | <person> |
| Status | active / expired / reverted |
| Issue | owner/repo#N |
| Expires | <date, and the upstream event if any> |
| Control relaxed | <what changes, from what to what> |

## Why
<the evidence: what breaks, measured, with links and run IDs; the cost of leaving the control as it is>

## Why not solved properly
<why the root cause cannot be fixed by us>

## Exact scope
<workflow and job ids, and the criteria that put a job in scope; what is explicitly out of scope>

## Compensating controls
<what still protects the asset>

## Residual risk
<in plain words, what an attacker or a mistake can now do>

## Expiry
<date, trigger, and what happens when it passes>

## Review trigger
<events that force a review before the expiry>

## Rollback
<the exact input or line to flip>

## Verification
<how the claim was proved and how to rerun it>
```
