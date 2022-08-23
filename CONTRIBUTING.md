# Contributing guide

Welcome to the Flashbots collective! We just ask you to be nice when you play with us.

Please start by reading our [code of conduct](CODE_OF_CONDUCT.md).

## Install dependencies

```bash
go install mvdan.cc/gofumpt@latest
go install honnef.co/go/tools/cmd/staticcheck@v0.3.1
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.48.0
```

## Test

```bash
make test
make test-race
make lint
```

## Code style

Start by making sure that your code is readable, consistent, and pretty.
Follow the [Clean Code](https://flashbots.notion.site/Clean-Code-13016c5c7ca649fba31ae19d797d7304) recommendations.

## Send a pull request

- Your proposed changes should be first described and discussed in an issue.
- Open the branch in a personal fork, not in the team repository.
- Every pull request should be small and represent a single change. If the problem is complicated, split it in multiple issues and pull requests.
- Every pull request should be covered by unit tests.

We appreciate you, friend <3.
