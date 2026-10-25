# Phonix v2.0 - CI/CD Compliance Gate Integration

The **Phonix CI/CD Compliance Gate** prevents unredacted secrets, unlicensed code symbols, and excessive LLM token usage from entering enterprise codebases and CI/CD automated review loops.

---

## 1. Overview
When automated CI/CD bots or developer tools invoke cloud LLMs for automated code review, PR summarization, or unit test generation, the Phonix Gate intercepts all egress traffic.

### Invariants Enforced:
1. **Zero-Trust AST Egress Proof**: Formally verifies via Z3 that **0 unredacted secrets, credentials, or internal IPs** leave the corporate perimeter.
2. **Context Frame Ceiling**: Guarantees AST frames are strictly sliced under `< 512 tokens/frame`, blocking bloated context attacks.
3. **Department Quota Protection**: Prevents CI/CD runners from exhausting monthly token quotas.

---

## 2. GitHub Actions Integration Example

Add `.github/workflows/phonix-gate.yml` to your repository:

```yaml
name: Phonix Zero-Trust Gate

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install Phonix Gateway
        run: |
          pip install .

      - name: Verify Formal Policy & Zero-Trust Invariants
        run: |
          phonix verify-policy --role engineer --dept engineering --unredacted-secrets 0

      - name: Scan Diff for Sensitive Literals
        run: |
          python -m pytest tests/test_semantic_sanitizer.py
```

---

## 3. Pre-Commit Hook Integration

Developers can run Phonix AST sanitization locally prior to committing:

```bash
# Verify policy before pushing commits
phonix status
phonix verify-policy --role contractor --dept engineering
```
