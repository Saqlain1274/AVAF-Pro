# AVAF Pro

**Academic Web Vulnerability Assessment Framework**

AVAF Pro is an academic web application security assessment framework developed as a Final Year Project (FYP). It is designed to demonstrate how modern web applications can be discovered, analyzed, validated, and documented through a browser-driven workflow.

The framework focuses on **evidence-based vulnerability assessment** rather than generating artificial findings. Browser-observed behavior is treated as the primary source of truth for the assessment process.

> **Academic / Authorized Testing Notice**
>
> AVAF Pro is intended for academic research, learning, and authorized security testing only. Do not use it against systems without explicit permission.

---

## Architecture

AVAF Pro is organized into three major phases:

```text
┌─────────────────────────────────────────────────────────────┐
│                         AVAF Pro                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Phase 1             Phase 2              Phase 3           │
│  Discovery &         Validation &         Reporting         │
│  Detection           Attack Simulation                      │
│                                                             │
│  Browser-driven  →   Evidence-based   →   Structured        │
│  observation         validation           reports           │
│                                                             │
└─────────────────────────────────────────────────────────────┘