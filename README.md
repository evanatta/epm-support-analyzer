# EPM Support Analyzer

Analyze a decrypted Windows, macOS, or Linux support-info archive. The web interface uses the same Python error rules and report format as the CLI.

## Web interface

Requirements: Python 3.9+ and Node.js 22.12+ (or 24 LTS). The Python server uses the standard library only. Run these commands from the repository root:

```
cd frontend
npm ci
npm run build
cd ..
python python/server.py
```

Open http://127.0.0.1:8765. The server binds only to `127.0.0.1`; use `--port` to choose a different port. Node.js is needed only to build or develop the interface.

The Support Info tool accepts `.zip`, `.tar`, and `.tar.gz` archives up to 200 MB including form fields. Select automatic platform detection or an explicit platform, then analyze. Results include category counts and severity, file paths, line ranges, timestamps, matching sample lines, skipped-file reasons, and notes. Download JSON or CSV from the report. CSV downloads protect spreadsheet formula cells.

Uploads are temporarily stored for analysis and deleted afterward. Reports are not automatically written to disk. The service accepts requests only from local hosts and local browser origins. It is a local tool, not an internet-facing server. Archive contents can require substantially more memory than the compressed upload; use trusted, decrypted support packages.

## Development

Start the API in one terminal from the repository root:

```
python python/server.py
```

Start Vite in a second terminal:

```
cd frontend
npm ci
npm run dev
```

Open the local URL printed by Vite, normally http://127.0.0.1:5173. Vite proxies `/api` to port 8765. The API also permits CORS requests from other localhost ports. If you change the API port, update the proxy in `frontend/vite.config.ts`.

## Command line

```
python python/epm_support_report.py support-info.zip --platform auto -o report.json
```

ZIP, TAR, compressed TAR, and extracted directories are supported by the CLI. Output formats: text, Markdown, JSON, CSV. See [Python usage](python/README.md) for options and binary log requirements.

## Tests

```
cd python
python -m unittest discover -s tests
```

Tests use synthetic archives, including the local upload API. Frontend component tests: `npm test` from `frontend`. Type checking and packaging: `npm run build` from `frontend`.
