# Contributing Guide

Thanks for your interest in improving `pmg`. Beyond bug fixes and features, we particularly value:

- Documentation improvements
- Bug reports
- Using `pmg` in your projects and sharing feedback

## Reporting a bug

Open a new issue with the `bug` label.

## Suggesting a feature

Open a new issue with the `enhancement` label.

## Developer Setup

### Requirements

- Go 1.27+
- Git
- Make

### Getting started

Clone your fork and build:

```shell
git clone https://github.com/YOUR_USERNAME/pmg.git
cd pmg
go mod tidy
make all
```

The built `pmg` binary will be available in the `bin` directory.

If you wish to install this binary on your system, make sure to copy it to a directory within your `$PATH`. 

## Development Workflow

1. Create a branch:

   ```shell
   git checkout -b feature/your-feature
   ```

2. Make your changes. Add tests for new code.

3. Run the test suite:

   ```shell
   make test
   ```

4. Commit with a [DCO](https://developercertificate.org/) sign-off (the `-s` flag is required):

   ```shell
   git commit -s -m "feat: add new feature"
   ```

5. Push and open a pull request:

   ```shell
   git push origin feature/your-feature
   ```

## Review tiers

The change sets the tier. The author does not.

| Tier | Change | Human review |
| --- | --- | --- |
| Low | Only docs or tests | Read the description and the `Testing` evidence. |
| Medium | All other changes | Review the diff. |
| High | The code that a Yes answer names | Read each changed line. Apply the `Always check` list in `REVIEW.md`. |

The author checks the change against the five questions below and states the tier in the `Risk`
section of the pull request. For a High change, the author names the question and each changed
location that makes the answer Yes. A location is a file together with a function, a declaration,
a key or a line range. Only the named code is High. The remaining diff is Medium. The reviewer
checks that the list is complete.

Dependabot does not state a tier. The reviewer checks the questions for an update from Dependabot.

A change to `REVIEW.md`, `CLAUDE.md` or `AGENTS.md` is Medium, because these files control the
automated review.

All tiers need one approval from a person. An approval from a bot does not count.

### 1. Decision

Does the change alter when PMG allows, blocks or prompts for a package?

- Yes: the mapping from an analyzer verdict to allow, confirm or block.
- Yes: what PMG does without a verdict, for example a timeout, an analyzer error or a cache miss.
- Yes: how PMG matches a trusted package, a blocked package, a cooldown or the insecure bypass.
- Yes: a refactor of the code that makes the decision. The reviewer confirms that the decision
  did not change.
- No: the text of a block message. A log line or a metric near the decision.

### 2. Access

Does the change widen what a sandboxed or enforced install can read, write, run or connect to?

- Yes: a new allowed path, a broader glob or a new allowed host in a profile or a preset.
- Yes: a removed mandatory deny. A fallback that runs the install without the sandbox.
- Yes: a new way for a user to add an allow rule.
- No: a change that narrows access. A change to how PMG reports a violation.

### 3. Precedence

Does the change alter which config source wins?

- Yes: the merge order of the cloud, managed, user and project config.
- Yes: an environment variable, a flag or a user config that overrides a managed config.
- Yes: a new default that turns a control off or makes it weaker.
- No: a new key that no decision reads. A comment in the config template.

### 4. Data

Can the change put a secret or private data into a log, an event or a cloud payload?

- Yes: a new field in an event or in a cloud sync payload.
- Yes: a log line that prints a URL, a header, an environment variable or a command line. Each of
  these can hold a token.
- Yes: a new host that PMG itself connects to.
- No: a log line that prints a package name, a version or a verdict.

### 5. Supply chain

Does the change alter how PMG is built, signed, released or installed on a machine?

- Yes: `.goreleaser.yaml`, `install.sh`, the installer packages or the download step of the Action.
- Yes: a workflow that holds a secret or has write permission. This includes a new version of an
  action in that workflow.
- Yes: a new version of the base image in the `Dockerfile`.
- Yes: what `pmg setup` installs, for example a certificate or a shim.
- No: a test workflow that has read permission only.

## Review rounds

An automated reviewer starts a new review for each commit. These rules keep the number of rounds
small.

- Fix a finding if it changes what a person does or if it closes a real hole. If it does not,
  resolve the thread with a reason.
- Push one commit for each review, not one commit for each finding.
- If the third review still has Important findings, stop. Change the approach or divide the pull
  request.
