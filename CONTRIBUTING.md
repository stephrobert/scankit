# Contributing to scankit

Thanks for your interest in scankit. It is the shared engine/findings/scoring/report
library behind pepin, pitstop and pavois, so changes here ripple to every consumer —
correctness and stability matter more than features.

## Ground rules

- **Behaviour lives here, not in the products.** If a change would make two consumers
  render, score or evaluate differently, it belongs in scankit. Never fork the behaviour
  into a product.
- **Keep the API small and stable.** Every exported symbol needs a doc comment starting
  with its name. Additive, backward-compatible changes are strongly preferred until 1.0.
- **Determinism.** Findings must stay sorted (severity → code → subject → message) so a
  scan of the same input always renders identically.

## Development

Requires Go 1.26+.

```bash
go build ./...
go vet ./...
go test -race ./...
golangci-lint run ./...      # zero findings expected (no lint exclusions)
```

Fuzz the parsers/renderers before touching them:

```bash
go test ./engine -run '^$' -fuzz '^FuzzEvaluate$' -fuzztime=45s
go test ./report -run '^$' -fuzz '^FuzzRenderers$' -fuzztime=45s
```

Install the pre-commit hooks (they mirror CI):

```bash
pre-commit install
pre-commit run --all-files
```

## Pull requests

1. Branch from `main` (`feat/<slug>`, `fix/<slug>`).
2. Keep the change focused; add or update tests for any behaviour change.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for the subject
   (`feat:`, `fix:`, `docs:`, `ci:`, `refactor:`, `test:`…), imperative, < 72 chars.
4. Ensure `go test -race ./...`, `go vet`, and `golangci-lint` are green.
5. Open the PR against `main`; CI must pass and a maintainer review is required before
   merge (the `main` branch is protected by a ruleset).

## Reporting bugs and vulnerabilities

- Functional bugs: open an issue using the templates.
- Security issues: **do not** open a public issue — follow [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
