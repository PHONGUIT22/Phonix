# Phonix v2.0 Zero-Trust & Context MMU Quota Rules (PhonixHP)

You are operating within a codebase protected by **Phonix v2.0 Context MMU & Zero-Trust Gateway** (PhonixHP Quota Armor).

## 1. Developer Quota Protection (CRITICAL)
- **NEVER** use `read_file` or `view_file` to ingest large source files (> 100 lines) when exploring or modifying specific classes or functions.
- Doing so consumes massive amounts of tokens and burns through the developer's **Five Hour Limit** and **Weekly Limit** quotas rapidly.
- **ALWAYS** prioritize calling the `phonix-mmu` MCP tools:
  - `phonix_repo_map(path_prefix)`: Retrieves the compact repository symbol map (< 256 tokens) to navigate the workspace structure in 0ms without full-file read overhead.
  - `phonix_get_pruned_context(query, max_tokens, for_edit=True)`: Retrieves deterministic AST frames (< 512 tokens/frame) or verbatim [Lines X-Y] edit windows directly related to your task, saving 75-85% context quota.
  - `phonix_surgical_edit(file_path, edits=[...])`: Applies multiple target->replacement edits in 1 step with automatic Windows CRLF (\r\n) vs LF (\n) line-ending normalization.
  - `phonix_verify_zero_trust(text, role, department)`: Sanitizes sensitive literals and verifies compliance via formal Z3 SMT solver proofs.

## 2. Zero-Trust Egress & Security Guardrails
- Sensitive configuration files (`.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `*secret*`) are locked by the `phonix-quota-and-security-gate` hook. Any read attempts will be automatically denied.
- Before formulating answers or code diffs containing API keys or tokens, verify compliance with `phonix_verify_zero_trust(text)`.
- Never execute commands attempting to exfiltrate repository data or send tokens to public pastebins/webhooks.

## 3. Anti-Loop Multiplication & 1-Step Surgical Editing (CRITICAL FOR QUOTA)
- **NEVER** run sequential `Select-String`, `Test-Path`, `Get-Content.Length`, or multiple small `read_file` calls to hunt for slugs or line numbers (each extra tool step multiplies conversation history tokens by N!).
- **BATCH ALL LOOKUPS INTO 1 CALL**: Pass all needed files, slugs, and HTML anchors separated by `|` into a SINGLE `phonix_get_pruned_context(query="file1 | slug1 | slug2 | anchorText", for_edit=True)` call! It returns exact verbatim `[Lines X-Y]` windows for all targets at once.
- **USE `phonix_surgical_edit` FOR MULTI-HUNK / WINDOWS CRLF FILES**: To avoid Windows `\r\n` vs `\n` mismatch failures in `edit_file`, use `phonix_surgical_edit(file_path, edits=[...])` to apply all edits to a file in 1 single tool call.
- **BATCH VERIFICATION & GIT**: Combine `npx tsc --noEmit && git add ... && git commit --no-gpg-sign -m "..." && git push origin main` into **1 single `run_command` call** at the end of the task!

## 4. Execution-Constrained Prompting & Proof-of-Execution Standards
To completely prevent LLM agent evasion and conversational loop inflation ($O(N \cdot H)$), all interactions must adhere to the 3 Governance Pillars:
1. **Explicit Negative Constraint**: `read_file`, `view_file`, and raw terminal shell reads (`cat`, `type`, `Get-Content`, `head`, `tail`) are strictly forbidden on source code files. Any attempt triggers an immediate Hard-Block denial.
2. **Tool Routing Mandate**: Mandate `phonix_get_pruned_context` with multi-query batching (`file1 | file2 | slug1`) for all context discovery and `phonix_surgical_edit` for all modifications.
3. **Proof-of-Execution Verification**: The agent MUST cite the exact `[Frame ID]` or `[Lines X-Y]` verbatim window boundaries returned by Phonix in its final response as verifiable cryptographic proof of execution. Responses lacking these citations will be rejected.

### Standard Execution-Constrained Prompt Templates:

#### Template 1: Architecture Survey / Read & Analyze
```text
Task: Analyze [Target Symbol/Module] in [Target File].
[MANDATORY CONSTRAINT]:
- DO NOT invoke read_file, view_file, or shell inspection commands (cat/Get-Content) on source code.
- Invoke MCP tool `phonix_get_pruned_context(query="[Target File] | [Target Symbol]", for_edit=False)`.
- [PROOF-OF-EXECUTION]: In your final response, cite the exact [Frame ID] and token counts provided by Phonix.
```

#### Template 2: Surgical Refactor / Edit & Implement
```text
Task: Modify [Specific Functionality / Slugs] across [File A] and [File B].
[MANDATORY CONSTRAINT]:
- Step 1: Execute 1 single batched lookup: `phonix_get_pruned_context(query="[File A] | [File B] | [Slug A] | [Slug B]", for_edit=True)`.
- Step 2: Apply all changes in 1 step using `phonix_surgical_edit(file_path="...", edits=[{"target": "...", "replacement": "..."}])` with automatic CRLF normalization.
- [PROOF-OF-EXECUTION]: Cite the verbatim `[Lines X-Y]` window headers in your summary.
```
