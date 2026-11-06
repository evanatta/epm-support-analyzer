# Support info error report

Counts errors and conditions that affect the endpoint in a decrypted EPM support-info package for Windows, macOS, or Linux, with log paths and matching line numbers.

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
- Windows agent traces (`.trace`, `.trace.N`), Linux agent logs including rotated `epm.log.N.gz` and `*.log-YYYYMMDD` files, and macOS `epm_status.txt` and diagnostics text files are scanned as text.
- Patterns are in `rules.py`, in three groups checked in order: status checks, EPM agent rules, and generic rules. Each rule has a name, severity, platforms, impact area, description, and regex. Status checks also set `files`, a regex that limits them to status files such as `initialInfo`, `epm_status.txt`, `systemextensionsctl_list.txt`, and `restart.txt`.
- Each line is lowercased before matching, so write patterns in lower case. The first matching rule wins. Lines matching `BENIGN` (for example `AWS_ERROR_SUCCESS`) are ignored.

## Impact areas

Each category belongs to one impact area: server connectivity, policy delivery and enforcement, elevation and sudo, user and identity resolution, agent service health, driver and system extension, agent configuration and integrity, authentication and sign-in, host system, or general errors. Reports list impact areas first, with the highest severity and total matches for each. JSON adds `impacts` and per-category `impact` and `description`; CSV adds an `impact` column.

## Tests

```
python -m unittest discover -s tests
```

The tests create synthetic packages and exercise both the CLI and the HTTP upload route.
