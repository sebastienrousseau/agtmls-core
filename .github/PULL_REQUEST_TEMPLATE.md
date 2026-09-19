## What this changes

## Evidence

- [ ] A test **fails** without this change and passes with it
- [ ] If it changes analysis behaviour, a case landed in `agtmls-spec/corpus/`
      in the **same** pull request — the corpus is how two implementations in
      two languages stay equivalent
- [ ] `--check` modes and generated artifacts are current

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
