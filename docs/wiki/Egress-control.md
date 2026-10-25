# Egress control

**Egress** is outbound network traffic from the runner. Controlling it limits where a
compromised step, dependency or action can send data. Full reference:
[README: Egress](../../README.md#egress).

## harden-runner on every job

[`step-security/harden-runner`](Glossary.md) is the **first step of every job**
(a test checks), so the policy is in place before anything else runs. The one exception is the egress policy
check (EX-0001, below): it runs before harden-runner, touches no network, and fails the job if a policy value is
not exactly `audit` or `block`.

| Mode | Behaviour | Used for |
|---|---|---|
| `audit` | Logs every outbound connection to the job summary; blocks nothing | The default, and how a list is *measured* |
| `block` | Refuses any host not in `allowed-endpoints` | Every adopted repository |

Turning it on in a caller is one line:

```yaml
with:
  egress-policy: block
```

## Known platform issue: westus2 (EX-0001)

GitHub-hosted runners in `westus2` break `block` (a DNS experiment makes the agent drop allowed IPs). Until
it is fixed upstream, jobs that hold no secret follow the `egress-policy-secretless` input (default `audit`),
and every job that can run in `block` on a Linux runner starts with the **egress canary**
(`.github/actions/egress-canary`; Linux-only because it needs `timeout` and `getent`, so macOS and Windows
matrix legs skip it), which fails in seconds with "rerun the job" instead of hanging. The scope, the evidence, the residual risk,
the expiry (2026-11-07 at the latest) and the rollback are in
[EX-0001](../security/exceptions/EX-0001-harden-runner-block-westus2.md).
Full description: [README](../../README.md#known-ci-platform-issue-westus2-ex-0001).

## Where the lists come from

Each workflow carries a **measured** allow-list as the default of `allowed-endpoints`: every host its
jobs reached across the calling repositories in a day of audit-mode runs. The runner's own
infrastructure is left out because the agent allows it itself. Some lists (`bash-ci.yml`,
`distro-allowed-endpoints`, `semgrep-allowed-endpoints`, `verify-published.yml`) were measured the other
way round: this repository runs them on itself in `block` mode, so a missing host fails *here*, named in the log,
before any caller meets it.

A host only **one** repository reaches (an apt repository, an installer its Dockerfile pulls) goes in that
caller's `extra-allowed-endpoints`, never in the shared default.

## Reading a block

A blocked connection shows up in the job log as:

```
domain not allowed: <host>
```

That is also how a **new dependency announces itself**: your build started talking to something new. Decide
whether that is expected; if so add the host to `extra-allowed-endpoints`.

## Gotchas (each cost real time)

- **The allow-list is ONE space-separated line.** A YAML literal block (`|`) keeps newlines, the agent matches
  nothing and blocks everything, including PyPI. Use one line or a folded block (`>`).
- **No wildcards.** `*.example.com` is not supported and invalidates the *whole* list.
- **Format is `host:port`**, sorted. A test holds every default to this.
- **Fedora/dnf can't be listed.** `dnf` takes its mirror from a metalink answer that differs per run, so no fixed host
  list stays green. Use `distro-egress-policy: audit` for those images, or add the mirrors you observed.
- **Kali and Parrot are pinned**, because their official redirectors answer each request with a different mirror. The
  default `distro-setup-command` rewrites the sources to a single stable host. A custom setup command loses that.
- **Snyk's hosts came from its docs**, because the first run's connections were logged as IP addresses only. Every
  Snyk-enabled repository has since run green under `block`, which is the measurement.
- **Containers a job starts are outside harden-runner's view.** The `distro` job runs an official image as root
  in a throwaway container, sharing the job's network namespace, so the egress block still applies. StepSecurity's
  "unmonitored container" finding on those jobs is accepted for that reason.

## Related: `disable-sudo`

Every harden-runner step sets `disable-sudo: true`, so a compromised step cannot become root. The only
exceptions are jobs that run a *caller's own* install command (which may legitimately say `sudo apt-get install ...`).
