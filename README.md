# Dual-Key Actuator Fence

**Problem space:** mission-critical automation (Lockheed-class public design lens)  
**Innovation:** Policy brain and actuator muscle are cryptographically split. Neither alone can complete a side effect.

A side effect requires:
1. `PolicyDecision` — allow/refuse + policy hash + inputs digest  
2. `ActuatorGrant` — half-life capability token bound to that decision  
3. `ExecutionReceipt` — post-condition evidence

If grant expires, inputs drift, or policy refuses, execution **fails closed**.


## Claim ceiling (independent reference)

This is an **independent GlacierEQ reference implementation** exploring a public problem shape.
It does **not** claim employment, affiliation, deployment, contract, endorsement, clearance,
proprietary access, or production use by the named company. Company names label *problem spaces*
and *public design lenses* only.


## Quick start

```bash
python3 -m unittest discover -s tests -v
python3 -m src.dual_key_fence
```

## Status

Wave 1 excellence seed · 2026-08-09T04:26Z

## Quality honesty

See [QUALITY.md](./QUALITY.md). This is a leveled **reference mechanism**, not a production system or employer affiliation claim.
