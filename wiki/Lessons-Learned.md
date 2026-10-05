# Lessons Learned

Each of these cost at least an afternoon. They are kept in on purpose: **the mistakes are the curriculum.**
The README's
[Lessons learned the hard way](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#lessons-learned-the-hard-way)
is the authoritative list; this page tells them as lessons with the principle underneath.

## 1. Same-looking identifiers are not interchangeable

**A tag's SHA is not a commit's SHA.** `git ls-remote --tags` lists an annotated tag twice; the `^{}` line is the commit.
Four of the first pins here pointed at tag objects. GitHub resolved them; Dependabot would not have.
*Principle: verify the thing you are pinning is the thing the tool expects, before the tool is the one to tell you.*

## 2. A config format can fail silently and completely

**harden-runner's allow-list is one space-separated line.** A YAML literal block keeps its newlines, the agent matches
nothing and blocks *everything*, including PyPI. A wildcard invalidates the whole list. A test now holds every default
to one sorted line of `host:port`.
*Principle: when a format is fragile, test the format, not just the values.*

## 3. The platform changed a default under you

**GitHub's immutable OIDC subject is on by default in newer repositories.** A repository created from mid-2026
sends `repo:OWNER@<owner-id>/REPO@<repo-id>:ref:...` as the token's `sub`, and an identity listing only the plain form rejects
it. Eight repositories failed every Doppler fetch on 2026-10-03. The identities now list **both** forms.
*Principle: accept both the old and new form of an identifier you do not control, and test the first push to main on any new repository.*

## 4. Allow-lists have a nested structure

**The Actions allow-list needs the subdirectory forms too.** `snyk/actions@*` does not cover `snyk/actions/setup`;
`github/codeql-action@*` does not cover `github/codeql-action/init`. And a composite action's own `uses:` lines count:
`aquasecurity/trivy-action` calls `aquasecurity/setup-trivy`, and every release job failed at start with no annotation.
*Principle: read what a dependency itself depends on before you allow it.*

## 5. A tool's documented fix may not work, so reproduce it

**Snyk's pip resolver refuses a universal lock.** It exits 2 on "Missing required packages" whenever a line names a package not
installed (marker-gated pins, extras). `--skip-unresolved=true` is Snyk's documented answer and changed nothing, measured on
four repositories. The workflow now scans a `pip freeze` of what the lock actually installed, written over the lock so the SARIF
names a real file.
*Principle: measure before believing the docs, and scan what actually ships rather than a description of it.*

## 6. The finding may belong to something you do not control

**Trivy's setuptools finding may be pip's.** pip vendors its own setuptools and msgpack under `pip/_vendor`, so upgrading
setuptools clears nothing. `pip uninstall -y pip` as the last build step does, and a runtime image has no use for pip anyway.
*Principle: find which file the scanner is really pointing at.*

## 7. Process rules can defeat their own purpose

**A required review count of one is a required admin override when one person holds write.** GitHub will not let an author approve
their own PR. And with dismiss-stale on, every Dependabot rebase dismissed the approval. Set the count to zero and let the required
check do the gating.
*Principle: a control that is always bypassed trains people to bypass; pick the control that is actually exercised.*

## 8. Don't store what you don't need

**Codecov needs no token on a public repository.** `use_oidc: true` and the job's own identity is enough. The token in every
uploading repository was one more thing to rotate for nothing.
*Principle: before managing a secret, check whether the system accepts an identity instead.*

## 9. Deleting is not the same as it being gone

**A deleted code-scanning configuration leaves its analyses in the API.** GitHub records the deletion as one empty analysis;
the old ones stay listed and look alive. The pull-request check summary is the truth.
*Principle: know which view is authoritative before trusting it.*

## 10. Observability arrives in an unhelpful form first

**The first block-mode run may log IPs, not names.** harden-runner's audit summary showed Snyk's hosts as addresses only, so that
list came from Snyk's docs and was confirmed by a clean run rather than measured first.
*Principle: say honestly where a list came from and what confirmed it.*

## 11. Concurrent humans and sessions collide

**Fetch the tags before you cut one.** Another session cut v1.3.0 while this one believed the latest was v1.2.0; the v1.2.1 that
followed would have moved every caller's pin backwards.
*Principle: read the shared state immediately before you write to it.*

## 12. Blast radius is decided by what shares an environment

**Every value in a Doppler config is exported.** A CI config sharing an environment with runtime secrets turns every runtime secret into
a CI secret in every job. Separate project, separate config, only the names the pipelines read.
*Principle: scope credentials by what reads them, not by convenience.*

## 13. Free-plan limits are an attack on your own budget

**Snyk's free plan meters tests per month across the account.** Ten repositories scanning on every push spent a month of Code tests
in one busy day (34 runs). Snyk now runs weekly by default; `snyk-on: push` is opt-in.
*Principle: model quota like any other shared resource; default to the cheap schedule.*

## Themes worth carrying into your own work

- **Make the rule a test.** A rule that is only written down is a wish.
- **Fail closed.** An unrecognised update type is never merged; an unreadable check is `UNKNOWN`, not `PASS`.
- **Separate the job with the code from the job with the power.**
- **Prefer identity to secrets**; where a secret is unavoidable, put it in one place that can be listed.
- **Record exceptions, with an expiry.** An exception that cannot expire becomes policy.
- **Say how you measured.**
