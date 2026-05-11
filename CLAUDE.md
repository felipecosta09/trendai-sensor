# Operating notes for Claude

Project-level conventions for anyone (human or Claude) landing changes in this
repo. Short and enforced — if something here is wrong, fix the file, don't
drift from it.

## Branching

- **Never commit directly to `main`.** Always cut a feature branch from
  `main` at current HEAD.
- Branch name: `<type>/<short-slug>` using the same conventional-commit
  prefix you'll use for the PR title. Examples:
  - `chore/v0.1.7-hardening` (a release-prep umbrella branch)
  - `fix/afpacket-shutdown-deadlock`
  - `feat/sensor-info-gauge`
- One logical change set per branch. Umbrella branches (`chore/vX.Y.Z-*`)
  are fine when shipping a coordinated release; otherwise keep scope tight.
- `main` moves forward by squash-merged PRs only. No fast-forwards, no
  direct pushes, no merge commits on `main`.

## Commits

- **Conventional Commits**, always. Prefix set in use:
  `fix`, `feat`, `refactor`, `perf`, `chore`, `docs`, `test`, `build`, `ci`.
- Subject line ≤ 72 chars, imperative mood, no trailing period.
- Scope in parens when it adds clarity:
  `fix(capture/afpacket): close fds on ctx cancel to unblock shutdown`.
- **One logical change per commit.** Don't batch an env rename with a
  buffer-reuse perf tweak. Exception: when two edits touch the same line
  and splitting would require a transient broken state, collapse them and
  say so in the body.
- Body explains the **why** (impact, trace, motivation), not the what —
  the diff is the what.
- Breaking changes get a `BREAKING:` line in the body **and** a
  `### Breaking` entry in `CHANGELOG.md`.
- Sign commits with the standard trailer:
  `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.
- Never use `--no-verify`, `--amend` on pushed commits, or force-push to
  shared branches.

## PRs

- Open against `main` with `gh pr create`.
- Title = first-line of the most important commit (or a summary for
  multi-commit PRs), conventional-commit prefixed.
- Body: `## Summary` (1–3 bullets, why not what) + `## Test plan`
  (checklist of what was / should be verified).
- CI must be green before merge. Three required checks today:
  `lint`, `test (race)`, `helm lint`. Check with `gh pr checks <N>`.
- **Squash-merge** — keeps `main` history one-commit-per-PR.
- Delete the branch after merge.

## Releases

Releases are driven by tags on `main`. The `.github/workflows/release.yml`
workflow triggers on `push: tags: 'v*'` and publishes the GHCR image
**and** the packaged Helm chart tarball to the GitHub release.

Every release PR must bump **both**:

- `Chart.yaml` → `version:` (chart SemVer) and `appVersion:` (string,
  `vX.Y.Z`, matches the image tag).
- `CHANGELOG.md` → new top-level section with the release date and
  appropriate sub-sections (`Breaking`, `Fixed`, `Added`, `Performance`,
  `Docs`). Omit sub-sections that don't apply.

Chart `version` tracks the sensor version 1:1 — we don't maintain an
independent chart SemVer. If you forget the bump, `release.yml` will
publish a tarball whose internal version disagrees with the tag, and
`helm install ...trendai-sensor-X.Y.Z.tgz` URLs will 404.

Tag flow:

```
# after PR is squash-merged to main
git checkout main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag triggers `release.yml`. Verify with `gh run watch` and check
[the releases page](https://github.com/felipecosta09/trendai-sensor/releases)
for the image and `.tgz` asset.

## Chart / values conventions

- `values.yaml` defaults must be **safe**. No placeholder IPs, no
  enabled-by-default endpoints the operator didn't ask for. Empty
  `sensor.ndrAddr` is parked mode, not "forward to 10.0.0.1."
- Observability is **opt-in** (`prometheus.enabled: false` by default).
  When gating a feature on a values key, gate all three surfaces: sensor
  env/flags, chart templates (annotations, ports), and the ServiceMonitor.
- Any new env var goes in three places: `values.yaml` (under `sensor.*`),
  `templates/configmap.yaml`, and the `Configuration` table in `README.md`.
- Breaking values-key renames get a CHANGELOG callout — no silent
  aliases.

## Code conventions

- **Capture paths** (TC-BPF and AF_PACKET) must both honor ctx cancel
  within a second. If you touch either path, verify graceful shutdown in
  CI via the unit tests and in-cluster via `kubectl delete pod`.
- **Single-goroutine assumptions** are documented on the struct
  (`forward.Forwarder.Send` is caller-single-threaded and uses a
  preallocated buffer — see [vxlan.go](internal/forward/vxlan.go)).
  Don't break the assumption without adding sync.
- **Prometheus counters/gauges** registered in
  [internal/metrics/prom.go](internal/metrics/prom.go) must be
  pre-instantiated at value 0 for every expected label so
  `rate(...)` / `group by (...)` work from t=0. Covered by
  `TestFilterDropsPreRegistered`.
- **No comments explaining what the code does.** Only comments
  explaining non-obvious **why** (hidden constraint, kernel semantic,
  bug workaround).

## Testing

- `make test` locally. The `//go:build linux` tests (AF_PACKET,
  TC-BPF-adjacent) won't run on darwin — rely on CI for those.
- `make lint` before pushing (go vet + golangci-lint). Must be clean.
- `helm lint .` before pushing chart changes.
- In-cluster verification for anything touching capture, shutdown, or
  the forwarder — see `Verification` section of the most recent release
  plan. The demo EKS cluster is the canonical smoke-test target.

## Docs

- `CHANGELOG.md` is the single source of truth for release notes. Don't
  duplicate into README.
- README URLs (install commands, tarball paths) must point at the
  **current** release tag. Bump them in the same PR that bumps
  `Chart.yaml`.
- New user-facing behavior gets a README section (example:
  `## Parked mode`, `## Observability`). Don't hide behavior behind
  "read the code."

## Things that are not fine

- Committing to `main` directly. No exceptions.
- Skipping the Chart.yaml bump — breaks the release tarball URL.
- Silent aliases for renamed env vars / values keys — if it's breaking,
  say so.
- Adding a Helm values default that forwards traffic somewhere the
  operator didn't configure.
- `--no-verify`, force-push to `main`, amending published commits.
- "Fix the test" by relaxing the assertion rather than diagnosing the
  actual defect. (See the PR #3 pipe-vs-socket wake-on-close episode for
  why this matters: the test was wrong about *what it was testing*, not
  about *whether the code worked*.)
