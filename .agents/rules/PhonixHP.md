# Phonix Context MMU (PhonixHP)

When `phonix-mmu` MCP tools are available:
- `read_file` is fine for files <= 300 lines or bounded `StartLine`/`EndLine` slices.
- `phonix_get_pruned_context(query="a | b | c")`: prefer for files > 300 lines or batching multiple targets.
- `phonix_surgical_edit(file_path, edits)`: prefer for multi-hunk or Windows CRLF edits.
- `phonix_symbol_impact(symbol)`: run before refactoring shared symbols (callers/callees in 1 turn).
- `phonix_run_compact(command)`: prefer for noisy test/build/lint/diff runs (`pytest`, `tsc`, `npm run build`, `git diff`).
