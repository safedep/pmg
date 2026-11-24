# Validate PMG on ARC runners behind a local Squid

This SOP checks which install paths PMG covers on a self-hosted GitHub Actions runner that Actions
Runner Controller (ARC) runs on Kubernetes. The runner container runs PMG with kernel enforcement
(`pmg-entrypoint.sh`), dockerd, and a local Squid. Jobs reach Squid through
`HTTPS_PROXY=http://172.17.0.1:3128`.

The operator runs one test workflow on one new runner Pod and compares each result with the table in
[Expected results](#expected-results).

## How coverage works

PMG checks a package download only when the connection leaves the Pod on port 80 or 443 from a
process inside the cgroup that PMG enforces on (`.../runner`), in the Pod's network namespace.

- PMG does not route port 3128. It routes Squid's own connection to the registry on 443, when Squid
  runs inside `.../runner`.
- A job step that skips Squid connects to 443 directly. PMG routes that connection too.
- dockerd starts containers in other cgroups and network namespaces. PMG covers a container or a
  build only when it uses Squid.
- Squid sends GitHub to a parent pool. PMG does not see that traffic.

![Install paths in the runner Pod](install-paths.svg)

## Files

| File | Purpose |
| --- | --- |
| [`pmg-sop.yml`](pmg-sop.yml) | The test workflow. Copy it to `.github/workflows/pmg-sop.yml` in a test repository |
| [`case.sh`](case.sh) | Runs one case and prints one verdict line. Copy it to `.github/pmg-sop/case.sh` |
| [`cgroup-check.sh`](cgroup-check.sh) | Reports whether Squid, dockerd and cron are inside the cgroup that PMG enforces on |

## Prerequisites

- [ ] A test runner pool with `replicas: 1` and its own label. All jobs then run on one Pod and one
      PMG daemon.
- [ ] A new Pod. Do not restart Squid or PMG by hand after the Pod starts.
- [ ] Squid starts as a child of the command that `pmg-entrypoint.sh` runs. It does not start from a
      lifecycle hook, a probe, cron or `kubectl exec`.
- [ ] If the Squid parent pool listens on port 80 or 443, its addresses are in
      `proxy.server.enforce.skip_destinations`.
- [ ] The PMG debug log is on. Set these variables on the runner container of the test pool. PMG
      then writes each decision to `/tmp/pmg-debug.log`. The variables reach PMG only when the runner
      container runs as root (`kubectl exec <pod> -- id -u` gives `0`). Otherwise use Step 4.

  ```yaml
  env:
    - name: APP_LOG_LEVEL
      value: debug
    - name: APP_LOG_FILE
      value: /tmp/pmg-debug.log
  ```

- [ ] A repository that can use the test pool. Step 2 adds the workflow to it.
- [ ] A git dependency repository `<org>/pmg-gitdep-test` with this `package.json`:

  ```json
  {"name": "pmg-gitdep-test", "version": "1.0.0", "dependencies": {"safedep-test-pkg": "*"}}
  ```

`safedep-test-pkg` is a harmless SafeDep test package that PMG blocks as malware.

## Step 0: check a Pod that let a package through (optional)

Do this step only when a Pod that installed a package PMG should block still runs. A new Pod starts
with clean state, so it can hide the cause. On that Pod, run Step 1, then Step 4. Then delete it and
continue with a new Pod.

## Step 1: check the Pod

Run these commands in the runner container with `kubectl exec`. Use `kubectl exec` only to read.
PMG does not route a process that `kubectl exec` starts, so run every install from the workflow.
In a container that runs as root, drop `sudo`.

1. PMG started with kernel enforcement. Expect `[pmg] attach to .../runner` and
   `daemon started ... with kernel enforcement`.

   ```bash
   kubectl logs <pod> | grep -E '^\[pmg\]|daemon started'
   ```

2. Squid, dockerd and cron are inside the enforced cgroup. Expect `ROUTED` on every line.
   `NOT ROUTED` for Squid stops the test. Fix how Squid starts, or use [Step 5](#step-5-attach-pmg-to-the-top-level-cgroup-last-resort).

   ```bash
   kubectl cp cgroup-check.sh <pod>:/tmp/cgroup-check.sh
   kubectl exec <pod> -- bash /tmp/cgroup-check.sh
   ```

3. PMG decrypts Squid's registry traffic. Expect `issuer: O=SafeDep PMG; CN=SafeDep PMG Proxy CA`.

   ```bash
   curl -sv -x http://172.17.0.1:3128 https://registry.npmjs.org/ -o /dev/null 2>&1 | grep -i issuer
   ```

4. PMG runs with the expected settings. Expect `Kernel enforcement: active (cgroup .../runner, ports 80,443, ...)`
   and `namespaces: ignore`. Keep the full output and the output of `pmg version` with the image tag.

   ```bash
   sudo pmg proxy status --state /run/pmg/proxy-state.json
   pmg version
   ```

5. Record the PMG block count.

   ```bash
   sudo sh -c 'cat /root/.config/safedep/pmg/logs/*-pmg.log' | grep -c '"event_type":"malware_blocked"'
   ```

6. The PMG debug log is on. Expect a number greater than `0`. With no file, or `0`, PMG did not get
   the variables from the Prerequisites.

   ```bash
   kubectl exec <pod> -- grep -c '"level":"debug"' /tmp/pmg-debug.log
   ```

## Step 2: run the workflow

The test runs as a GitHub Actions workflow on the test runner pool, so every install runs as a job
step does.

1. Pick a repository that can use the test pool, for example a new private repository in the same
   organization. With an organization-level pool, the runner group of the pool must allow that
   repository. `workflow_dispatch` shows **Run workflow** only for a workflow on the default branch.

2. Find the label of the test pool. Use the custom label, not `self-hosted`, so that the jobs run only
   on the test pool.

   ```bash
   kubectl -n <runner-namespace> get runnerdeployment <test-pool> -o jsonpath='{.spec.template.spec.labels}'
   ```

3. In a clone of that repository, add the workflow and the helper script, and replace the
   placeholders. `PMG_REF` is the PMG branch that holds this SOP.

   ```bash
   PMG_REF=chore/pmg-sop-kubernetes-self-hosted-arc
   BASE=https://raw.githubusercontent.com/safedep/pmg/$PMG_REF/docs/runbooks/arc-squid-validation
   mkdir -p .github/workflows .github/pmg-sop
   curl -fsSL -o .github/workflows/pmg-sop.yml "$BASE/pmg-sop.yml"
   curl -fsSL -o .github/pmg-sop/case.sh "$BASE/case.sh"
   chmod +x .github/pmg-sop/case.sh
   sed -i 's/<runner-label>/<test-pool-label>/g; s#<org>#<your-org>#g' .github/workflows/pmg-sop.yml
   ```

   If the runners pull images from an internal registry, also replace `node:22-slim` with the path of
   that image in the registry.

4. Commit and push to the default branch.

   ```bash
   git add .github && git commit -m "Add the PMG validation workflow" && git push
   ```

5. Start the workflow: **Actions** > **pmg-sop** > **Run workflow**, or `gh workflow run pmg-sop.yml`.

6. Make sure the jobs ran on the test Pod. In each job, **Set up job** shows the runner name. It must
   be the name of the test Pod.

   ```bash
   kubectl -n <runner-namespace> get pods | grep <test-pool>
   ```

Each case prints one line, for example:

```text
T1a BLOCKED rc=1 pmg_blocks=+1 at 17:52:36
```

A case counts as blocked by PMG only when `pmg_blocks` rises. Squid also answers 403 when its ACL
refuses a client. In T5 and T6, read the block count with Step 1, check 5.

After the run, repeat Step 1, checks 2 and 5.

## Expected results

| ID | Install path | Expected |
| --- | --- | --- |
| T1a | Job step, npm through Squid | Blocked |
| T1b | Job step, npm with no proxy variables | Blocked |
| T1c | Job step, `curl` of the test tarball through Squid | 403 |
| T2a | `docker run` through Squid | Blocked when the container trusts the PMG CA. TLS error when it does not |
| T2b | `docker run` with no proxy variables | Installed (not covered) |
| T3a | `docker build` with no proxy build-arg | Installed (not covered) |
| T3b | `docker build` through Squid, PMG CA in the image | Blocked |
| T4a | Git dependency | The git source installs unchecked. Its registry dependency is blocked |
| T5 | Job container (`container:`) | Blocked with `HTTPS_PROXY` and the CA. Installed with no proxy |
| T6 | Container action (`uses: docker://`) | Same as T5 |

On a GitHub-hosted runner with PMG 0.36.1 and a Squid stand-in, T1 to T4 and T6 gave these results,
also with BuildKit for T3. The runner passes the job's `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` into
a container action. `NODE_EXTRA_CA_CERTS` names a file on the runner, which the container does not
have, so npm fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` until the container gets the CA at that path.

## Step 3: when a result does not match

Find the case's request in the Squid log (the last step of the `host` job):

| Squid log line | Meaning |
| --- | --- |
| `TCP_TUNNEL/200 ... HIER_DIRECT/<ip>` | Squid dialled the registry. PMG must see it |
| `... PARENT/<peer>` | Squid sent it to the parent pool |
| `TCP_DENIED/403` | Squid's ACL refused the client. The 403 is not from PMG |
| No line | The tool did not use Squid |

| Result | Cause | Action |
| --- | --- | --- |
| T1a installs, `HIER_DIRECT` | Squid is outside `.../runner` | Fix how Squid starts. Use a new Pod. If that is not possible, go to Step 5 |
| T1a installs, T1c gives 200 | PMG decrypts but does not block. Most often a failed analysis | Read PMG's decisions (below) |
| T1a installs, T1c gives 403 | npm uses another registry, proxy or `noproxy` (see T0) | Fix the npm config |
| T1b installs | The step runs outside `.../runner` (see T0) | Collect T0 output and `kubectl logs` |
| `E403`, `pmg_blocks=+0` | Squid's ACL refused the client | Allow the client address in Squid |
| `TLS-ERROR` in a container or build | PMG decrypted it, the container does not trust the PMG CA | Add the CA |
| T5 or T6 fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | `NODE_EXTRA_CA_CERTS` names a runner path that the container does not have | Mount the CA at that path in the container |

### Read PMG's decisions

Read the debug log with `kubectl exec`, and keep a copy for the record.

```bash
kubectl exec <pod> -- grep -aE 'Analyzing package|Analysis complete|Failed to analyze|circuit breaker|Blocking|No registry config|unresolved' /tmp/pmg-debug.log
kubectl exec <pod> -- cat /tmp/pmg-debug.log > pmg-debug.log
```

| Debug log | Meaning |
| --- | --- |
| `Analyzing package`, then `Blocking malicious package` | PMG works. The request path differs. Use the tables above |
| `Failed to analyze package` | PMG cannot reach the analysis service and allows the package |
| `circuit breaker is open` | PMG allows packages for 30 seconds without analysis |
| No line for the package | The request did not reach PMG's registry check |

## Step 4: debug a Pod that runs without the debug log

Use this step for a Pod that already runs without the debug log variables, such as the Pod in Step 0,
or for a runner container that does not run as root. These commands replace the daemon with a debug
daemon and keep the Pod. Run them with `kubectl exec`.

1. Stop the entrypoint's supervisor, then stop PMG.

   ```bash
   cg=$(sudo sed -n 's/.*"cgroup_path": *"\([^"]*\)".*/\1/p' /run/pmg/proxy-state.json | head -1)
   sudo touch /run/pmg/stopping; sleep 3
   sudo pmg proxy stop --state /run/pmg/proxy-state.json
   ```

2. Start PMG with `--debug` on the same cgroup.

   ```bash
   sudo setsid nohup env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
     pmg --debug proxy start --enforce --enforce-cgroup "$cg" --state /run/pmg/proxy-state.json \
     > /tmp/pmg-debug.log 2>&1 < /dev/null &
   sleep 5; sudo pmg proxy status --state /run/pmg/proxy-state.json
   ```

3. Run the workflow again, then read the decisions as in [Read PMG's decisions](#read-pmgs-decisions).

Delete the Pod after this step.

## Step 5: attach PMG to the top-level cgroup (last resort)

Use this step only when a process that must go through PMG, such as Squid, runs outside `.../runner`,
and its start cannot move into the command that `pmg-entrypoint.sh` runs. Examples are a process that
a lifecycle hook, an exec probe, an outside supervisor or `kubectl exec` starts.

`pmg-entrypoint.sh` moves the processes of the runner container into the child cgroup `runner`, so
that dockerd can give cgroup controllers to its containers. PMG attaches to `runner`. A process that
starts later from outside the entrypoint's process tree lands in the container's top-level cgroup,
and PMG does not route it. This step attaches PMG to the top-level cgroup, which also covers
`runner`.

1. Stop the entrypoint's supervisor and PMG, then start PMG on the top-level cgroup. Run with
   `kubectl exec`:

   ```bash
   top=$(sudo sed -n 's/.*"cgroup_path": *"\([^"]*\)".*/\1/p' /run/pmg/proxy-state.json | head -1)
   top=${top%/runner}
   sudo touch /run/pmg/stopping; sleep 3
   sudo pmg proxy stop --state /run/pmg/proxy-state.json
   sudo env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
     pmg proxy start --daemon --enforce --enforce-cgroup "$top" --state /run/pmg/proxy-state.json
   ```

2. Repeat Step 1, checks 2 to 4. Expect `ROUTED` for Squid, and `Kernel enforcement: active` on the
   path without `/runner`. Then run the workflow again.

What changes:

| Process | Attached to `runner` | Attached to the top-level cgroup |
| --- | --- | --- |
| Job steps and processes that the entrypoint starts | Routed | Routed |
| Processes that `kubectl exec`, an exec probe or a lifecycle hook starts | Not routed | Routed |
| Containers on a Docker bridge | Not routed | Not routed |
| `--network host` containers on a cgroup v2 node | Not routed | Routed. They need the PMG CA, or registry installs fail |
| `--network host` containers on a hybrid cgroup node | Not routed | Not routed. dockerd puts them outside the Pod's cgroup |

This step was tested on a hybrid cgroup node. The cgroup v2 row follows from the cgroup layout and is
not tested.

Limits:

- The change lasts until the runner container restarts. A new container starts PMG on `runner` again.
- The supervisor stays off. If PMG stops, nothing starts it again.
- A permanent change needs support in `pmg-entrypoint.sh`.

## Known gaps

| Gap | Cases | Options |
| --- | --- | --- |
| A build or container that does not use Squid | T2b, T3a, T5, T6 | A `proxies` block in the runner user's `~/.docker/config.json`, or PMG's nftables redirect for containers. Both need the PMG CA in the container |
| Git dependencies | T4a | PMG checks registry downloads only. Refuse `github:` and `git+` specs in a lockfile check, or deny the GitHub fetch in Squid |
| Squid outside `.../runner` | Step 1, check 2 | Start Squid from the entrypoint's command. As a last resort, Step 5 |

## Cleanup

- [ ] Delete the test Pod.
- [ ] Remove `APP_LOG_LEVEL` and `APP_LOG_FILE` from the pool before it runs normal jobs.
- [ ] Remove `safedep-test-pkg` from any lockfile that the test changed.

## After validation

To send events to SafeDep Cloud and apply the cloud policy, put `SAFEDEP_API_KEY` and
`SAFEDEP_TENANT_ID` in the Secret files that `pmg-entrypoint.sh` reads. When the image supplies its own
`/etc/safedep/pmg/config.yml`, the entrypoint does not change it, so set `cloud.enabled: true` in that
file.
