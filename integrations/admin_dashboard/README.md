# Phonix v2.0 - Admin Dashboard & Observability Integration

The **Phonix Admin Dashboard** provides centralized enterprise observability for engineering leadership, CISO teams, and FinOps administrators.

---

## 1. Key Observability Metrics

| Metric Dimension | Source Module | Business Value |
|---|---|---|
| **Cost Avoidance ($)** | `src/gateway/audit_telemetry.py` | Dollars saved by routing simple tasks to the on-device 1B local fast-path instead of cloud APIs. |
| **AST Pruning Ratio (%)** | `src/micro_router/` | Percentage of irrelevant repository context discarded prior to cloud prompt dispatch (typically 60-80% reduction). |
| **Zero-Trust Egress Violations** | `src/gateway/policy_engine.py` | Count of attempted data leaks and contractor egress violations blocked by Z3 formal verification. |
| **Speculative Cache Hit Rate** | `src/mmu/file_trie.py` | Percentage of streaming JSON requests whose referenced files were pre-staged at 0ms latency. |
| **Department Token Quotas** | `config/zero_trust_policy.yaml` | Live consumption tracking against monthly department token ceilings. |

---

## 2. Telemetry Endpoints

### `GET /health`
Returns live health, indexed file counts, and aggregated audit metrics:
```json
{
  "status": "ok",
  "version": "2.0.0",
  "architecture": "Zero-Trust AST Paging & 1B Micro-Router",
  "telemetry": {
    "total_requests": 1420,
    "buffered_entries": 1420,
    "violations_blocked": 12,
    "total_tokens_processed": 582100,
    "estimated_cost_saved_usd": 29.105,
    "avg_latency_ms": 32.4
  },
  "indexed_files": 412
}
```

---

## 3. SIEM & Datadog Exporter Configuration

Export telemetry directly to enterprise SIEM tools (Splunk, Elastic) or Datadog using OpenTelemetry:

```yaml
telemetry:
  otlp_endpoint: "https://otlp.datadoghq.com:4318/v1/traces"
  export_interval_seconds: 10
  sample_rate: 1.0
  compliance_audit_log_path: "/var/log/phonix/audit.jsonl"
```
