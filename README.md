# OSINT Evidence Capture Tool

MSc Cyber Security project artefact — Objectives 3 and 4.

A Flask web application for logging OSINT evidence with automatic:
- SHA-256 hashing
- EXIF metadata extraction
- OpenTimestamps blockchain timestamping (via direct calendar server API, bypassing a known Windows compatibility bug in the opentimestamps-client CLI)
- Append-only SQLite audit logging
- Admiralty Code source reliability rating

## Setup
1. `python -m venv venv`
2. `venv\Scripts\activate`
3. `python -m pip install -r requirements.txt`
4. `python app.py`

## Author
Shashank A00084168 — Roehampton MSc Cyber Security