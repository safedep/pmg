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

- Go 1.25+
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
