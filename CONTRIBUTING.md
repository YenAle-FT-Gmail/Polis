# Contributing to Polis

Thank you for your interest in contributing to the Polis decentralised protocol stack.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Install dependencies:
   ```bash
   cd node && poetry install
   cd ../crypto && cargo build
   ```
3. Run the test suite:
   ```bash
   cd node && poetry run pytest --cov=polis_node -q
   ```

## Development Workflow

1. Create a feature branch from `main`: `git checkout -b feat/my-feature`
2. Make your changes with clear, atomic commits.
3. Ensure all tests pass and coverage stays above **80 %**.
4. Run the linters:
   ```bash
   poetry run black --check polis_node tests
   poetry run ruff check polis_node tests
   poetry run mypy polis_node
   ```
5. Open a Pull Request against `main`.

## Code Standards

- **Python**: Black formatting (line-length 100), Ruff linting, mypy strict types.
- **Rust**: `cargo fmt` and `cargo clippy --all-targets`.
- All public functions and classes must have Google-style docstrings.
- Every new feature must include tests. No PR will be merged that drops coverage.

## Invariants

Before submitting code that touches cryptography, storage, or moderation, review
[INVARIANTS.md](INVARIANTS.md). Breaking an invariant requires an RFC.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add delegation chain verification
fix: correct CID computation for empty payloads
docs: update API spec with /moderation routes
test: add integration tests for multi-node propagation
```

## Reporting Issues

- Use GitHub Issues with a clear title and reproduction steps.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
