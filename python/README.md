# Support info error report

Counts error instances in a decrypted EPM support info package (Windows, macOS or Linux) and lists the log path and line numbers for each.

## Requirements

- Python 3.9 or later. No extra packages needed.
- Optional: `pip install python-evtx` to read Windows `.evtx` event logs.

## Run

```
python epm_support_report.py <support-info.zip | folder> [--platform auto|windows|macos|linux] [-o report.txt|.md|.json|.csv] [--context N]
```

Without `-o` the report prints to the screen. With `-o` it is written to that file, and the extension picks the format.

## Notes

- Inputs: `.zip`, `.tar`, `.tar.gz` or an extracted folder, including nested zips.
- Basic only: `.evtx` needs `python-evtx`; Procmon `.pml` must be exported to CSV in Procmon; a macOS `.logarchive` is read with `log show` on macOS only; Linux `.journal` files need `journalctl`.
- Error rules are starter patterns in `rules.py`. Add a rule by adding an entry with a name, severity, platforms and regex.
- Tests: `python -m unittest discover -s tests`

## Samples wanted

Masked support info packages from each platform, plus an `.evtx` export, a Procmon CSV/PML and a macOS `.logarchive`, so the rules can be tuned.
