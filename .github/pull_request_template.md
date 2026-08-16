## Description

Brief description of what this PR does.

## Changes

- [ ] New feature / flag
- [ ] Bug fix
- [ ] Documentation
- [ ] CI / infrastructure
- [ ] Refactor

## Checklist

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Kernel path still compiles (if `oxideutils-core` changed):
      `cargo build -p oxideutils-core --no-default-features --features alloc,disasm,kernel`

## Testing

Describe how you tested this change.

## Related issues

Closes #
