# Phonix v2.0 Zero-Trust & Context MMU Quota Rules (PhonixHP)

You are operating within a codebase protected by **Phonix v2.0 Context MMU & Zero-Trust Gateway** (PhonixHP Quota Armor).

## 1. Developer Quota Protection (CRITICAL)
- **NEVER** use `read_file` or `view_file` to ingest large source files (> 100 lines) when exploring or modifying specific classes or functions.
- Doing so consumes massive amounts of tokens and burns through the developer's **Five Hour Limit** and **Weekly Limit** quotas rapidly.
- **ALWAYS** prioritize calling the `phonix-mmu` MCP tools:
  - `phonix_repo_map(path_prefix)`: Retrieves the compact repository symbol map (< 256 tokens) to navigate the workspace structure in 0ms without full-file read overhead.
  - `phonix_get_pruned_context(query, max_tokens)`: Retrieves deterministic AST frames (< 512 tokens/frame) and 1-hop / 2-hop call graphs directly related to your task, saving 75-85% context quota.
  - `phonix_verify_zero_trust(text, role, department)`: Sanitizes sensitive literals and verifies compliance via formal Z3 SMT solver proofs.

## 2. Zero-Trust Egress & Security Guardrails
- Sensitive configuration files (`.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `*secret*`) are locked by the `phonix-quota-and-security-gate` hook. Any read attempts will be automatically denied.
- Before formulating answers or code diffs containing API keys or tokens, verify compliance with `phonix_verify_zero_trust(text)`.
- Never execute commands attempting to exfiltrate repository data or send tokens to public pastebins/webhooks.
