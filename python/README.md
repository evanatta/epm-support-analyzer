# Support info error report

Counts error instances in a decrypted EPM support-info package for Windows, macOS, or Linux, with log paths and matching line numbers.

## Requirements

- Python 3.9 or later. The CLI and local web server use the standard library.
- Optional: `pip install python-evtx` to read Windows `.evtx` event logs.

## CLI

Run from this directory:

```
python epm_support_report.py <support-info.zip | folder> [--platform auto|windows|macos|linux] [-o report.txt|.md|.json|.csv] [--context N]
```

Without `-o`, the report prints to the screen. With `-o`, it is written to that file; the extension selects the format.

## Web interface

Build the React interface once with Node.js 22.12+ (or 24 LTS), starting from this directory:

```
cd ../frontend
npm ci
npm run build
cd ../python
python server.py
```

Open http://127.0.0.1:8765. The server binds only to `127.0.0.1`. An optional `--port 8766` changes the port. It serves `frontend/dist` when built; the API also works without that folder.

For development, run `python server.py` here, then `npm run dev` in `frontend` in a separate terminal. Open Vite's printed local URL. Vite proxies API calls to port 8765; update `frontend/vite.config.ts` if the Python port changes.

The interface has one tool: Support Info. Upload a decrypted `.zip`, `.tar`, or `.tar.gz`, optionally choose a platform, and inspect error categories, severity, file counts, line ranges, timestamps, sample lines, skipped files, and notes. Reports can be downloaded as JSON or CSV.

### Local API

- `GET /api/health` returns `{"ok": true}`.
- `POST /api/analyze` accepts multipart fields `file` and optional `platform` (`auto`, `windows`, `macos`, `linux`). The JSON matches the CLI JSON format; `source` is the upload's filename, not a temporary path.
- Maximum request body: 200 MB including multipart fields. Empty files, invalid archives, and invalid platforms are rejected.
- One analysis runs at a time. Additional requests receive status 503 while it is busy.
- Uploads are deleted after analysis; the server does not save reports. CORS is limited to local browser origins. Do not expose this server to the internet. Use trusted archives; decompressed data can require much more memory than the upload size.

## Log support

- Inputs: `.zip`, `.tar`, `.tar.gz` or an extracted folder, including nested zips.
- `.evtx` needs `python-evtx`; Procmon `.pml` must be exported to CSV in Procmon.
- macOS `.logarchive` requires macOS and `log show`; Linux `.journal` requires `journalctl`.
- Error patterns are in `rules.py`. Each rule specifies a name, severity, platforms, and regex.

## Tests

```
python -m unittest discover -s tests
```

The tests create synthetic packages and exercise both the CLI and the HTTP upload route.
