# AVAF Pro

## Academic Web Vulnerability Assessment Framework

AVAF Pro is an academic web vulnerability assessment framework developed as a Final Year Project (FYP).

The framework is designed to discover, analyze, and validate web application attack surfaces using browser-driven observation and evidence-based processing.

---

## Project Purpose

The goal of AVAF Pro is to provide an academic framework for studying automated web application security assessment.

The system focuses on:

- Browser-based application discovery
- Dynamic runtime observation
- Network observation
- Parameter discovery
- Behavioral surface discovery
- Evidence-based candidate generation
- Vulnerability validation
- Structured reporting

AVAF Pro is designed for authorized academic and testing environments.

---

# Architecture

AVAF Pro is organized into three major phases:

```text
Target Application
       |
       v
+----------------------+
| Phase 1              |
| Discovery & Detection|
+----------------------+
       |
       v
+----------------------+
| Phase 2              |
| Validation           |
+----------------------+
       |
       v
+----------------------+
| Phase 3              |
| Reporting            |
+----------------------+