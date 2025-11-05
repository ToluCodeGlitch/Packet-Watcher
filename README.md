# Packet Guardian — v1 (Static GitHub Pages Site)

A beginner-friendly static website that detects simple suspicious network flows from pasted or uploaded log files.
This is a client-side (browser-only) PoC suitable for GitHub Pages.

## Features
- Paste logs or upload a `.txt` log file.
- Simple detectors:
  - Byte-threshold detection (sum of bytes to a dest)
  - Consecutive increasing packet-size detection
- Download a CSV report of alerts.
- No server or backend required — runs in the browser.

## How to use
1. Clone this repo or copy the files to a folder.
2. Open `index.html` in your browser (or host via GitHub Pages).
3. Paste logs into the text area or upload a `.txt` log file.
4. Adjust detector settings and click **Run Detector**.
5. If alerts appear, download the CSV report and escalate as needed.

## Recommended next steps (v2+)
- Add timestamps parsing and sliding time-window logic.
- Support PCAP parsing (via wasm-based decoders) or server-side tshark.
- Add IP WHOIS / geolocation lookups.
- Add authentication and a simple backend for shared reports.

## License
MIT — see LICENSE file.
