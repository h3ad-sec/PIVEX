# PIVEX

**Investigation Pivot Graph — Part of [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/)**

PIVEX is an interactive graph that maps how to pivot between artifact types during a security investigation. Select a starting artifact, follow edges to discover related pivot paths, and export your investigation chain.

## Features

- 36 artifact nodes across Network, Endpoint, Identity, Email, and Cloud categories
- 168+ directed edges showing pivot relationships between artifact types
- Force-directed layout with alternative circle, concentric, and grid views
- Pivot path builder — click through a chain of artifacts to construct an investigation path
- Copy path as text or export as CSV (with MITRE ATT&CK technique and data source columns)
- Per-node info panel: description, data sources, outbound pivots, MITRE technique tags
- Focus mode to isolate a subgraph
- Dark / light theme with matrix rain background

## Artifact Categories

| Category | Count | Examples |
|----------|-------|---------|
| Network | 14 | IP, Domain, URL, SSL Cert, JA3, ASN |
| Endpoint | 16 | Hash, Process, Registry, Mutex, Named Pipe, DLL |
| Identity | 3 | User, Identity, RDP Session |
| Email | 2 | Email, Attachment |
| Cloud | 1 | Cloud Resource |

## Live Tool

[h3ad-sec.github.io/PIVEX](https://h3ad-sec.github.io/PIVEX/)

## Part of H3AD-SEC

PIVEX is a sub-tool under [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/), the threat hunting hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.


## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, THREATBRIEF-AI, PERSONA-AI, DEBRIEF-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE, MALBRIEF-AI, EVTXPARSE, ARTIFACTDB |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | DEBRIEF-AI, CASEBOARD |
