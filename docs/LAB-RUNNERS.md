# Lab runners: the Proxmox templates, planned before the box exists

This is the plan for moving the trusted half of CI onto a Proxmox host in the
lab: which VM templates exist, how each is built, how a runner lives and dies,
how it is networked, and how the shared workflows pick one. It is written so
the first day with the hardware is spent building, not deciding. Nothing here
is built yet; the roadmap's items 20 to 26 point at this page.

## The rule that shapes everything

**A self-hosted runner never runs a pull request.** A fork's pull request runs
the fork's code; on a hosted runner that is GitHub's problem, on a lab runner
it is a foothold inside the network. So:

- Pull-request jobs stay on GitHub-hosted runners, exactly as today.
- Lab runners take jobs that run from trusted refs only: a push to the default
  branch, a `v*` tag, a `schedule`, or a `workflow_dispatch` by a collaborator.
  That is the trusted-refs rule the Doppler gate already enforces, applied to
  compute.
- Every lab runner is **ephemeral**: it registers with `--ephemeral`, takes one
  job, and the VM is destroyed and recloned from its template. Nothing a job
  writes survives it.
- A runner holds **no long-lived secret**. Registration uses a just-in-time
  runner token minted by a GitHub App installed on the organisation (or, until
  the org move, a fine-grained token scoped to runner administration held only
  by the controller, never inside a runner). Jobs get secrets the way they do
  today: OIDC to Doppler, nothing on disk.

## Where it runs

- **Host**: the Proxmox node that is being set up for this (not the Librem Mini
  that runs the red-team lab; those VMs are deliberately vulnerable and must
  not share a host with anything that holds a GitHub identity). Specs are not
  known yet; the sizing below assumes at least 8 cores and 32 GB so three
  runners can run at once.
- **Network**: one new VLAN, `ci-runners`, with no route to any other lab VLAN.
  pfSense allows outbound only to the hosts the workflows already measure for
  harden-runner (the `allowed-endpoints` lists in the shared workflows are the
  starting rule set) plus the lab's own caches below. Inbound: nothing. The
  controller reaches runners over the Proxmox API, not SSH into the VM.
- **Storage**: templates on local NVMe for clone speed; a clone must take
  seconds, since one is made per job. Linked clones from a template disk.

## The templates

Every template follows one recipe (next section) and differs only in the base
image and the label it registers with. Names are `rt-<distro>-<version>-<arch>`.

| Template | Base | Why it exists | Label |
|---|---|---|---|
| `rt-ubuntu-24.04-amd64` | Ubuntu 24.04 cloud image | The default runner, same userland as GitHub's `ubuntu-24.04`; carries docker so container jobs and the distro matrix run unchanged | `lab-ubuntu-24.04` |
| `rt-debian-12-amd64` | Debian 12 generic cloud | Debian stable as a real system: systemd, apt, Python 3.11 | `lab-debian-12` |
| `rt-debian-13-amd64` | Debian 13 generic cloud | Debian trixie, Python 3.13; the Raspberry Pi OS userland on amd64 | `lab-debian-13` |
| `rt-kali-rolling-amd64` | Kali cloud image (or Debian 13 + Kali repo) | What the security tooling actually ships on | `lab-kali` |
| `rt-parrot-amd64` | Parrot Core netinstall, cloud-init added | The laptop target for Hammunition and the Skid Finder | `lab-parrot` |
| `rt-fedora-42-amd64` | Fedora Cloud Base | The Qubes template userland; dnf, which the container matrix cannot egress-pin | `lab-fedora-42` |
| `rt-ubuntu-24.04-arm64` | Ubuntu 24.04 arm64 cloud image | Native arm64 builds and tests, if the cluster gets an ARM node (Pi 5 or an Ampere board); until then QEMU on the Proxmox host, slow but real | `lab-arm64` |
| `rt-debian-13-arm64` | Debian 13 arm64 | Raspberry Pi OS Trixie, native | `lab-debian-13-arm64` |

Pop!_OS, Xubuntu and Kubuntu are not templates: they share Ubuntu's userland
and nothing this CI does touches a desktop. Qubes is not a template: its
templates are Debian or Fedora, both above.

Sizing per runner VM: 4 vCPU, 8 GB, 40 GB disk for the Ubuntu template (docker
layers), 4 vCPU, 4 GB, 20 GB for the rest. Three concurrent runners is the
starting cap; the controller holds the rest of the queue.

## The recipe every template follows

Built by a script in this repository (`scripts/lab/build-template.sh`, to be
written) so a template is reproducible and its drift is a diff:

1. **Base image**, pinned by checksum, imported with `qm importdisk`; cloud-init
   drive attached; serial console; QEMU guest agent on.
2. **cloud-init user-data** (one file per distro, same shape):
   - a `runner` user, no password, no SSH key (there is no SSH; the controller
     uses the guest agent and the API),
   - unattended security updates off (the template is rebuilt weekly instead,
     so every runner is identical and the rebuild is the patch),
   - packages: git, curl, jq, ca-certificates, python3, the distro's build
     essentials, and on the Ubuntu template docker-ce from Docker's repo pinned
     to the version the hosted runner image ships,
   - the GitHub Actions runner tarball, pinned by version and sha256, unpacked
     to `/opt/runner`, owned by `runner`, with `.runner` config NOT created
     (registration happens at clone time),
   - a systemd unit `runner.service` that reads `/etc/runner/jit.json` (the
     just-in-time configuration the controller injects via cloud-init at
     clone time), runs `run.sh --jitconfig`, and on exit calls
     `systemctl poweroff`. The controller sees the VM stop and destroys it.
3. **Hardening**: no sudo for `runner` except on the Ubuntu template, where
   docker needs it; `disable-sudo` in harden-runner is then honest everywhere
   else. Firewall inside the VM is the pfSense rule set repeated with nftables,
   so a misconfigured VLAN does not silently open egress. Auditd on, logs
   shipped to the SIEM (below) before poweroff.
4. **Smoke test at build**: boot the fresh template once with a dummy jitconfig
   that fails fast, confirm the unit started and the agent answered, then
   convert to template. A template that does not pass is not promoted.
5. **Rebuild weekly** on the lab's schedule from the same script, so the
   runner image is never older than seven days; the previous template is kept
   one week for rollback.

## The controller

A small service on the Proxmox host (Python, in this repository under
`scripts/lab/`, or actions-runner-controller if the lab Kubernetes arrives
first). Its loop:

1. Poll the organisation's (or each repository's) queued jobs that request a
   `lab-*` label, through the GitHub App with `actions: read`.
2. For each, mint a JIT runner config scoped to that repository and label set
   (`POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`), with
   `ephemeral: true`.
3. Clone the matching template (`qm clone --full 0`), attach a cloud-init
   snippet carrying the jitconfig, start it. Cap at three running.
4. Watch for the VM to stop; destroy it; log the job id, duration and
   template to the SIEM.
5. A runner that is still running after the job's `timeout-minutes` plus
   five is destroyed regardless.

The App's private key lives on the Proxmox host only, readable by the
controller's user; it is the one durable credential in the design, and it can
do nothing but register runners.

## How a workflow picks a lab runner

No caller rewrites its jobs. The shared workflows gain one input per CI
workflow, `trusted-runner` (default empty): when set to a label such as
`lab-ubuntu-24.04`, a job that is running from a trusted ref (push to the
default branch, tag, schedule, dispatch) uses it; a pull request keeps
`ubuntu-24.04`. The expression is the same one the Doppler gate uses, so there
is one definition of "trusted". `runners` and `distro-runners` already take
labels, so a caller that wants the OS matrix on real VMs lists
`lab-debian-13`, `lab-parrot` and friends there; the audit's composition rule
is unchanged.

What moves to the lab first, in order:

1. The weekly audit (`audit.yml`), whose read-only token then never leaves the
   lab. This is the proof the controller works end to end.
2. The nightly image verification (`verify-published.yml` callers).
3. Default-branch and tag runs of the OS matrix on real VMs; pull requests
   keep the container matrix on GitHub.
4. Native arm64 image builds, once an ARM node exists.
5. The staging deploy (roadmap 26): a lab runner starts each daemon's new
   `latest` against test accounts in a `staging` namespace and watches its
   healthcheck for ten minutes before the tag is called good.

## Caches, so the lab stops depending on the WAN

- **Zot** as a pull-through registry for `python:*-slim`, the distro images
  and the action images; `registry-1.docker.io` and `ghcr.io` in the runner
  VLAN's egress rules are then replaced by the cache's address.
- **devpi** as a PyPI proxy; `--require-hashes` still verifies every wheel, so
  the cache changes nothing about trust.
- Both on a small VM in the lab's services VLAN with a one-way rule from
  `ci-runners`. Their logs are the inventory of what CI downloads.

## What this does not change

The baseline, the audit, the signed releases, the egress lists and the
Dependabot flow are untouched. A lab runner is another place the same
workflows run, with a stricter network and no secret at rest.

## Decisions still open

- Organisation move (roadmap 16) before or alongside: runner groups and the
  self-hosted policy become one org setting instead of 21 repository settings.
  Strongly preferred before the controller is written.
- ARM node: a Pi 5 is enough for the arm64 template; an Ampere board is
  enough to also build images natively. Decide once the amd64 half works.
- Where the SIEM ingests runner audit logs: Wazuh agent in the template, or
  the existing Suricata/OpenSearch path from the VLAN's traffic. Wazuh gives
  per-job process trails, which is what a compromised-runner investigation
  needs.
