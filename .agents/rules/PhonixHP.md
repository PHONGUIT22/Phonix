# Phonix Smart Gate (PhonixHP)

- **Small/Quick** (1-4 files <= 400 lines, `git`, `npm install`): use native `read_file` / `edit_file` / `run_command`.
- **Survey / Overview**: **MUST** call `phonix_repo_map` first (not bulk `read_file`).
- **Large File (> 400 lines) / Multi-Target**: **MUST** batch in `phonix_get_pruned_context(query="a | b | c")`.
- **Shared Symbol Refactor**: **MUST** call `phonix_symbol_impact(symbol)` first for callers/callees.
- **Test / Build / Lint** (`pytest`, `tsc`, `npm run build`, `eslint`): **MUST** call `phonix_run_compact(command)`.
- **Multi-Hunk / CRLF Edits**: use `phonix_surgical_edit(file_path, edits)`.
