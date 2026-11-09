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

The change sets the tier. The author does not. If a pull request touches paths in more than one
tier, the highest tier applies. State the tier in the `Risk` section of the pull request.

| Tier | Change | Human review |
| --- | --- | --- |
| Low | `docs/`, other Markdown files, test-only changes, dependency updates from Dependabot | Read the description and the `Testing` evidence. |
| Medium | All other changes | Review the diff. |
| High | `proxy/`, `analyzer/`, `internal/flows/`, `sandbox/`, `internal/netenforce/`, `config/`, `truststore/`, `.github/workflows/`, `action/`, `action.yml`, `install.sh`, `.goreleaser.yaml` | Read each changed line. Apply the `Always check` list in `REVIEW.md`. |

A change to `REVIEW.md`, `CLAUDE.md` or `AGENTS.md` is Medium, because these files control the
automated review.

All tiers need one approval from a person. An approval from a bot does not count.
