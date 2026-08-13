# CI

CI runs in two places, for one reason: GitHub-hosted runners are unavailable
on this account.

| Where | Platform | Config | Always on |
|---|---|---|---|
| GitLab CI | Linux | `.gitlab-ci.yml` | yes |
| GitHub Actions, self-hosted | Windows | `.github/workflows/ci.yml` | only while the runner is up |

GitHub remains the canonical home. GitLab is a runner and nothing else.

## GitLab

GitLab's free tier includes 400 compute minutes a month, which is far more
than this project needs, and its runners are ephemeral — so unlike the
self-hosted setup there is no reason to restrict which events may trigger it.

Getting commits there does **not** need GitLab's mirroring features, which are
Premium. Push to both remotes instead:

```bash
git remote set-url --add --push origin https://github.com/firatmio/mcp-audit-proxy.git
git remote set-url --add --push origin https://gitlab.com/<user>/mcp-audit-proxy.git
```

After that a plain `git push` reaches both.

The pipeline pins `golang:1.24` — the *minimum* version `go.mod` declares,
not the newest. That way CI proves the `go 1.24` directive is honest instead
of quietly relying on whatever newer toolchain the maintainer has installed.

Every job has been run inside that exact image (Go 1.24.13, linux/amd64):
build, vet, gofmt, tidy, tests, `-race`, all five cross-compile targets, the
end-to-end demo with its detector assertions, and the npm packaging including
the `apt-get install nodejs` step, which yields Node 20 and satisfies the
launcher's `engines: >=18`.

To repeat it without pushing:

```bash
docker run --rm -v "$PWD:/src" -w /src -e GOTOOLCHAIN=local golang:1.24 \
  bash -c 'go test ./... && CGO_ENABLED=1 go test -race ./...'
```

## Why also self-hosted

Not a preference — GitHub-hosted runners are unavailable on this account, and
every job is refused before a step runs:

```
The job was not started because your account is locked due to a billing issue.
```

Self-hosted runners are free, consume no billable minutes, and are not covered
by that lock. A job requesting one queues and waits for a runner instead of
being rejected.

## The security constraint, and why the triggers look like that

A self-hosted runner executes workflow code on a machine somebody owns. On a
**public** repository that is dangerous in one specific way: if `pull_request`
triggered this workflow, anyone could open a PR whose steps run arbitrary code
on that machine.

So `.github/workflows/ci.yml` triggers only on events a maintainer can cause:

```yaml
on:
  push:
    branches: [main]   # only a maintainer can push here
  workflow_dispatch:   # manual
```

There is no `pull_request` trigger. Contributions are tested by pulling the
branch locally and running `go test ./...`.

**Do not add a `pull_request` trigger** without first moving to ephemeral
runners (a container or VM discarded after each job). GitHub's
"require approval for first-time contributors" setting reduces the risk but
does not remove it: approval is per contributor, not per change, so someone
whose first PR is approved can run whatever they like in the second.

## Setting up the runner

GitHub → repository **Settings → Actions → Runners → New self-hosted runner**,
then follow the commands it shows. They are generated per repository and
include a registration token.

Two things the generic instructions do not tell you:

**Run it as your own user.** The race detector step looks for a C toolchain in
`$HOME/scoop/apps/mingw/current/bin`. A runner installed as a Windows service
under a different account will not find it, and the step fails loudly rather
than silently skipping — which is intended, but means the runner has to be
your user for it to pass.

**Git Bash must be present.** Every step declares `shell: bash`, so the runner
uses Git Bash. It is already there if you use `git` from a terminal.

The runner keeps its own working copy under `_work/`, separate from your
checkout, so `actions/checkout` cleaning the workspace cannot touch your local
files.

## What the workflow does

One job, sequential steps, because a single runner executes one job at a time
and a matrix would only queue:

| Step | Checks |
|---|---|
| Build | `go build ./...` |
| go vet | |
| gofmt | fails and prints a diff if anything is unformatted |
| go.mod is tidy | fails if `go mod tidy` would change anything |
| Test | `go test ./...` |
| Test with `-race` | finds the mingw toolchain, then the full suite |
| Cross-compile | all five release targets |
| End-to-end demo | runs `scripts/demo.sh` and asserts all three detectors fired |
| npm packaging | assembles all six packages, never publishes |

The end-to-end step is the one worth keeping. Every unit test once passed while
the detectors were silently unwired — responses never reached the policy
engine — and only an assertion against the real output would have caught it.

## When Actions is unblocked

If the billing lock is resolved, moving back to GitHub-hosted runners means
restoring the matrix (Linux, macOS, Windows) and re-adding the `pull_request`
trigger, which is safe there. That version is in git history:

```bash
git log --oneline --all -- .github/workflows/ci.yml
```

The README's CI badge was removed for the same reason and can be restored from
history too.
