# AVAF Pro

## Academic Web Vulnerability Assessment Framework

AVAF Pro is a browser-driven academic web vulnerability assessment framework developed as a Final Year Project.

The framework is designed to discover and assess web application attack surfaces using real browser-observed behavior.

## Main Architecture

AVAF Pro consists of three major phases:

### Phase 1 — Discovery & Detection

Phase 1 uses Playwright-based browser discovery to observe the target application.

It collects evidence such as:

- Browser-observed pages
- Routes
- Forms
- Parameters
- Interactive controls
- Runtime behavior
- Network requests
- API-related observations
- XHR/fetch activity
- WebSocket observations
- Browser state changes
- Interaction-derived evidence
- Screenshots of observed application states

The discovery process is dynamic and does not rely on predefined application routes or wordlists.

### Phase 2 — Validation

Phase 2 consumes the evidence produced by Phase 1 and performs controlled validation of discovered candidates.

Only findings supported by sufficient attack-specific evidence are treated as confirmed results.

### Phase 3 — Reporting

Phase 3 generates reports from validated findings.

The reporting layer presents discovered and validated security information in a structured format.

## Technology Stack

- Python
- Playwright
- PySide6
- HTML
- JavaScript
- Matplotlib

## Project Structure

```text
phase1_scanning_detection/
├── crawler_playwright.py
├── parameter_scanner.py
├── QueueManager.py
├── decision_Engine.py
├── deduplication.py
├── runtime_behavior_processor.py
├── discovery/
├── behavior/
├── interaction/
├── runtime/
├── session/
├── builders/
├── models/
└── output/
```
