# Keeping a project board current

**What this is.** [project-sync](Workflow-project-sync.md) keeps a GitHub Projects v2 board
in step with the issues and pull requests of the repositories that call it. This page
explains why it uses a GitHub App and never a personal token, what the App can and cannot
do, and the two problems measured on its first live run.

## Why it exists

A board is only useful if it is current, and a board that depends on someone dragging cards
is not. GitHub's built-in project workflows react inside GitHub in seconds but have no
"add every issue from this repository", no done date and no repair for a missed event. The
workflow adds an item when it opens, moves it to Done with the close or merge date, and a
weekly reconcile repairs what an event missed.

## What it does

| Event | Result |
|---|---|
| Issue opened | Added if absent; the open-issue status when it has none |
| Issue reopened | Back to the open-issue status if it was Done (the done date is cleared) |
| Pull request opened, ready, reopened | Added if absent; the PR status, or the draft status while a draft |
| Closed, merged | Done, with the done date set to the close or merge date |
| Weekly schedule, manual run | Reconcile: walk the board and the repository once, in pages of 100, adding what is missing and moving closed items to Done; never reopens, never changes an open item's status |

It never touches a field it was not told about, and it never calls `updateProjectV2Field`,
because that mutation regenerates a field's option ids and wipes the values across the board.
A field or option name it cannot find is refused before anything changes, with a sentence
naming the field and listing the options it does have. `dry-run: true` prints every change
and makes none.

## Why an App, and never a personal token

The only credential is a **GitHub App installation token**. There is no personal access token
path and no fallback; a test holds that. The workflow fetches the App's private key from
Doppler over the job's OIDC identity and trades it, through `actions/create-github-app-token`,
for a token that:

- lives one hour,
- is scoped to the calling repository's installation,
- is revoked by the action when the job ends,
- and names the **App** in the audit log, not the maintainer.

A personal token acts as a person, holds whatever that person holds, and does not expire
unless someone sets it to. The App holds Projects read and write plus read on issues and pull
requests, in the six or so repositories it is installed on, and nothing else.

**What it can do:** add items to the project, set their fields, and read issues and pull
requests, only in the installed repositories.
**What it cannot do:** write code, issues or pull requests, read anything else, or act outside
the installation. To revoke it, delete the key or uninstall the App; either ends every token
it can mint, and one already minted dies within the hour.

**It is for organization-owned projects only.** GitHub Apps have no user-account Projects
permission (Projects is listed under Organization permissions only), so a token cannot write
to a user-owned project, and the script refuses a `/users/` URL before any API call.

## Why the caller uses `pull_request_target`

A `pull_request` run from a fork gets a read-only token and no secrets, so a fork's pull request
could never reach the board. `pull_request_target` runs the caller's workflow file from the
**base** branch, with secrets. It is dangerous only when the job then checks out and runs the
pull request's code. This job does neither: it has no checkout at all, and its one step is the
script inlined from this repository, which reads the event payload as JSON data and never
expands it into a shell. The pull request's title and body are never read. Do not copy that
trigger into a caller that checks out the pull request.

Two measured consequences, both from the first live callers on 2026-10-05:

- **zizmor flags the trigger** (`dangerous-triggers`) in the caller itself, which every caller's
  workflow lint then fails on (issue #91). The fix is a `# zizmor: ignore[dangerous-triggers]`
  on that line with the reason beside it.
- **The Doppler identity refuses it** (issue #93): the subject on that event is
  `repo:OWNER/REPO:pull_request`, which the `ci` identity must never match. The proposed fix is a
  separate Doppler project holding only the App key, with its own identity; see
  [Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md). Both issues were open when this page was
  written.

A smaller third: `actions/create-github-app-token` deprecates its `app-id` input in favour of
`client-id`, and the first run printed the warning (issue #92, open).

## Setting up the App, once

1. Create a GitHub App (name it for what it does). Uncheck **Webhook, Active**: it receives no
   events.
2. Permissions: **Organization** Projects read and write; **Repository** Issues read, Pull requests
   read. Metadata read is added automatically. Nothing else.
3. Install it on the organization, **Only select repositories**, and pick only the repositories that
   call the workflow.
4. Note the App id (an identifier, not a secret) and generate a private key.
5. Store the key in Doppler with `scripts/doppler-ci-set.sh --from-file <key.pem> PROJECTS_APP_PRIVATE_KEY`
   (the name is fixed), and delete the downloaded file; Doppler holds the only copy.
6. On each calling repository set the variable `PROJECTS_APP_ID`.

Then add the caller to one repository, run it by hand with `dry-run: true`, read the log
(`dry run: would SetSelect {...}`), remove the flag and run again. The project's own built-in workflows
(Item closed to Done, Pull request merged to Done, Item added to Backlog) complement it: they react in
seconds, and both set the same value, so order does not matter.

## What this refuses to do

It never writes to a user-owned project, never uses a personal token, never regenerates a
field, never overwrites an Area, Kind, Priority, Epic or Effort already set, and never checks out
or reads a pull request's text.
