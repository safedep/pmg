
# Contributing Guide

You can contribute to `pmg` and help make it better. Apart from bug fixes,
features, we particularly value contributions in the form of:

- Documentation improvements
- Bug reports
- Using `pmg` in your projects and providing feedback

## How to contribute

1. Fork the repository
2. Add your changes
3. Submit a pull request

## How to report a bug

Create a new issue and add the label `bug`.

## How to suggest a new feature

Create a new issue and add the label `enhancement`.

## Development workflow

When contributing changes to repository, follow these steps:

1. Ensure tests are passing
2. Ensure you write test cases for new code
3. `Signed-off-by` line is required in commit message (use `-s` flag while committing)

## Developer Setup

### Requirements

- Go 1.24+
- Git
- Make

### Getting Started

1. Clone your fork:

```shell
git clone https://github.com/YOUR_USERNAME/pmg.git
cd pmg
```

2. Install dependencies:

```shell
go mod tidy
```

3. Build the project:

```shell
make all
```

### Development Workflow

1. Create a branch:

```shell
git checkout -b feature/your-feature
```

2. Make your changes and test:

```shell
make test
```

3. Commit with sign-off:

```shell
git commit -s -m "feat: add new feature"
```

4. Push and create PR:

```shell
git push origin feature/your-feature
```
