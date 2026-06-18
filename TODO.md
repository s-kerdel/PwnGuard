# TODO

## Linting & complexity enforcement

Ruff and complexipy are configured/installed but run manually only. Wire them
into automation when ready.

- [ ] Add a CI lint job (`.github/workflows/`) running:
  - `ruff check .`
  - `ruff format --check .`
  - `complexipy .`
- [ ] Add `.pre-commit-config.yaml` so the same checks run on `git commit`.

### Ruff cleanup (currently 608 findings under `select = ["ALL"]`)

- [ ] Review `SLF001` (152) — cross-object private member access.
- [ ] Review complexity hits (`C901`, `PLR0912/0913/0915`) — candidates for refactor.
- [ ] Review security `S*` findings — confirm which are intentional test fixtures
      vs. real issues before fixing.
- [ ] Run `ruff check --fix` + `ruff format` for the safe modernization fixes
      (`PTH*`, `FA100`/`UP*`, `I001`, `E501`).
- [ ] Decide whether to ignore opinionated rules (`PLR2004`, `ARG001/002`, `PLC0415`).
