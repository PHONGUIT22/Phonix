# Phonix v2.0 - Technical Architecture Specification

> **Systems Architecture & Formal Verification Manual**  
> *Zero-Trust AST Paging & 1B Micro-Router Gateway*

---

## 1. High-Level Vision & Problem Statement

Modern enterprise generative AI deployments suffer from two compounding failures:

```
[Developer Request] 
      │
      ├──> [Unbounded Retrieval: Whole Files / RAG Noise] ──> High Latency & Token Waste ($$$)
      │
      └──> [Direct Cloud Egress: Credentials / PII / IP]  ──> Compliance & Regulatory Breach
```

### The Phonix Solution
Phonix v2.0 implements an in-process, hardware-bounded **Context Memory Management Unit (Context MMU)** coupled with an edge-quantized **1B Micro-Router SLM** and a **Formal Policy Gateway**:

```
[Developer Request]
      │ (Streaming HTTP)
      ▼
┌────────────────────────────────────────────────────────┐
│  CONTEXT MMU                                           │
│  ├─ 0ms Speculative FileTrie Ingestion                 │
│  ├─ Deterministic Tree-sitter Slicing (< 512 tok/frame)│
│  ├─ Static 1-Hop / 2-Hop Call-Graph Expansion (BFS)    │
│  └─ Pinned KV Prefix Cache (vLLM / llama.cpp)          │
└──────────────────────────┬─────────────────────────────┘
                           │ Candidate AST Frames
                           ▼
┌────────────────────────────────────────────────────────┐
│  SEMANTIC-PRESERVING SANITIZER & Z3 POLICY ENGINE      │
│  ├─ Redact Literals Only (Keep 100% Identifiers)       │
│  ├─ Z3 SMT Formal Egress & Quota Proof                 │
│  └─ Ephemeral Bidirectional Vault                      │
└──────────────────────────┬─────────────────────────────┘
                           │ Sanitized Context
                           ▼
┌────────────────────────────────────────────────────────┐
│  1B MICRO-ROUTER (1.2GB VRAM, Q4_K_M)                  │
│  Locked strictly by router_decision.gbnf:              │
│  1. AST Context Pruning                                │
│  2. Complexity Scoring for Circuit Breaking            │
└────────────┬─────────────────────────────┬─────────────┘
             │ Complexity < 0.70           │ Complexity >= 0.70
             ▼                             ▼
┌───────────────────────────┐ ┌──────────────────────────┐
│ LOCAL FAST PATH (On-Device│ │ CLOUD DISPATCHER         │
│ Zero Latency / Free)      │ │ (Claude 3.5 / GPT-4o /   │
└────────────┬──────────────┘ │  DeepSeek Fallback)      │
             │                └────────────┬─────────────┘
             └──────────────┬──────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│  VAULT REHYDRATOR & AUDIT TELEMETRY                    │
│  ├─ Restore Original Literals into Response            │
│  └─ Log FinOps & Zero-Trust Audit Trail                │
└────────────────────────────────────────────────────────┘
```

---

## 2. Context MMU (Memory Management Unit)

The Context MMU treats repository code not as raw unstructured text, but as **paged virtual memory frames** structured by syntax trees.

### 2.1. Speculative 0ms I/O via FileTrie (`src/mmu/file_trie.py`)
- Standard gateways wait for the entire HTTP JSON payload to finish transmission before reading referenced files.
- Phonix v2.0 indexes the repository tree into an in-memory prefix trie.
- As raw bytes arrive in HTTP chunks, `SpeculativeInspector` scans token prefixes (e.g. `"files": ["src/gate...`).
- When a path prefix matches a trie node, the MMU initiates disk read and AST slicing **in parallel with the incoming network stream**, achieving effectively **0ms perceived I/O latency**.

### 2.2. Deterministic AST Slicing (`src/mmu/ast_slicer.py`)
- Source files are parsed into semantic boundaries (function definitions, class interfaces, module-level bindings).
- **Strict Frame Ceiling**: Every frame is bounded to **strictly < 512 tokens**.
- If a function exceeds 512 tokens, it is subdivided into basic-block sub-frames (`func#part1`, `func#part2`) preserving scope headers.
- **Transpilation Invariant**: Code transpilation using heavy SMT solvers is strictly avoided. Slicing is purely deterministic Tree-sitter / AST parsing.

### 2.3. Static 1-Hop / 2-Hop Call-Graph Expansion (`src/mmu/call_graph_pager.py`)
- Instead of naive vector cosine similarity, the pager constructs a deterministic directed call graph $G = (V, E)$:
  - $V$: Set of AST frames.
  - $E$: Directed edges representing `calls`, `inherits`, and `imports`.
- Given entrypoint seed symbols $S$, the pager runs Breadth-First Search (BFS):
  - **1-hop**: Immediate callees and caller interfaces.
  - **2-hop**: Transitive dependencies required to resolve type signatures.
- Context is truncated once the frame token budget ($B \approx 2048$ tokens) is met.

### 2.4. Pinned KV Prefix Cache (`src/mmu/kv_prefix_cache.py`)
- Pinned prefixes (system instructions, enterprise zero-trust rules, foundational types) are held in memory.
- Matches prefix hashes directly against runtime KV cache slots in llama.cpp / vLLM, eliminating recomputation of system prompts.

---

## 3. Micro-Router (1B Local SLM / LoRA)

### 3.1. Hardware Envelope (`config/hardware_profile.yaml`)
- **Model**: Llama-3.2-1B-Instruct or Qwen2.5-Coder-1.5B.
- **Quantization**: `Q4_K_M` GGUF.
- **VRAM Budget**: Strictly capped at **1.2 GB** (1228.8 MB), allowing continuous co-existence on developer workstations alongside IDEs and background tasks.

### 3.2. Strict GBNF Grammar Locking (`router_decision.gbnf`)
To eliminate hallucinations, the SLM's output logits are masked at each generation step by a formal GBNF grammar. The output is guaranteed to strictly adhere to:

```json
{
  "selected_ast_frames": ["src/mmu/ast_slicer.py::slice_code::hash"],
  "drop_irrelevant_frames": ["src/utils/legacy.py::helper::hash"],
  "routing_decision": {
    "task_category": "refactor",
    "complexity_score": 0.88,
    "trigger_cloud_handoff": true
  }
}
```

The 1B model performs **ONLY two tasks**:
1. **AST Context Pruning**: Separates task-critical frames from irrelevant distractor frames.
2. **Complexity Scoring & Circuit Breaking**: Computes task complexity score ($c \in [0.0, 1.0]$) and sets `trigger_cloud_handoff`.

---

## 4. Enterprise Compliance & Cost Gateway

### 4.1. Semantic-Preserving AST Sanitizer (`src/gateway/semantic_sanitizer.py`)
Traditional sanitizers blindly regex-replace code, corrupting function signatures and break AST parsing.  
Phonix v2.0 enforces **Semantic-Preserving Sanitization**:
- **Untouched (100% Intact)**: Function names, variable names, class names, method calls, type annotations, control structures.
- **Redacted (Literals Only)**: String/numeric literals matching sensitive regex/AST patterns (AWS credentials, JWTs, private keys, RFC1918 IPs, PII).
- Replaced by typed placeholders: `<REDACTED_AWS_KEY_01>`, `<REDACTED_IP_01>`.
- Reverse mapping stored in an ephemeral, request-scoped vault.

### 4.2. Z3 Formal Zero-Trust Policy Engine (`src/gateway/policy_engine.py`)
Formal verification uses the Z3 SMT solver to prove safety theorems prior to cloud egress:

#### SMT Theorem Formulation
Let:
- $E \in \{\text{True}, \text{False}\}$ be the decision to egress to cloud.
- $S \in \mathbb{N}$ be the count of unredacted secrets.
- $R \in \{\text{admin}, \text{engineer}, \text{contractor}, \text{auditor}\}$ be user role.
- $B_d, C_d, T \in \mathbb{N}$ be department budget, consumed tokens, and requested tokens.

The safety invariant $\Phi_{\text{safe}}$ is defined as:
$$\Phi_{\text{safe}} \iff (E \implies (S = 0)) \land (E \implies \text{CanEgress}(R)) \land (C_d + T \le B_d)$$

The Z3 solver checks satisfiability of the violation condition:
$$\text{Solver}.\text{Check}(\neg \Phi_{\text{safe}})$$
- If $\text{Check} = \text{UNSAT}$: **Mathematically Proven Safe**. The request is permitted.
- If $\text{Check} = \text{SAT}$: **Violation Detected**. The request is rejected or degraded to local execution.

---

## 5. Dual-Path Execution & Circuit Breakers

| Condition | Selected Path | Latency | Cost |
|---|---|---|---|
| Complexity $< 0.70$ or Role = Contractor | **Local Fast Path** (`src/execution/local_fast_path.py`) | $< 50\text{ ms}$ | **$0.00** |
| Complexity $\ge 0.70$ & Proven Safe | **Cloud Dispatcher** (`src/execution/cloud_dispatcher.py`) | $\sim 500\text{ ms} - 2\text{ s}$ | Metered per 1k tok |

### Upstream Fallback Hierarchy
1. Primary: Anthropic Claude 3.5 Sonnet
2. Secondary Fallback: OpenAI GPT-4o
3. Tertiary Fallback: DeepSeek Coder V3
4. Final Fallback: Local Fast Path

---

## 6. Moat Flywheel (`moat_flywheel/`)

The proprietary moat compounds through continuous telemetry:
1. `GitDiffHarvester`: Collects commits, PR diffs, and modified symbol graphs.
2. `DatasetBuilder`: Reconstructs the exact context frames required for past PRs.
3. `RouterLoRATrainer`: Fine-tunes the 1B SLM on AST pruning accuracy, maximizing context compaction before cloud calls.

---

## 7. Performance Characteristics & Benchmarks

| Metric | Target | Phonix v2.0 Pragmatic Architecture |
|---|---|---|
| **VRAM Footprint** | $\le 1.2\text{ GB}$ | 1.15 GB with Q4_K_M 1B SLM |
| **AST Frame Size** | $< 512\text{ tokens}$ | Strictly sliced by `ASTSlicer` |
| **Speculative I/O Latency** | $\approx 0\text{ ms}$ | Parallel HTTP chunk stream trie matching |
| **Cloud Token Reduction** | $\ge 65\%$ | Frame pruning via GBNF 1B router |
| **Zero-Trust Egress Leaks** | **0** | Formally verified via Z3 SMT solver |
