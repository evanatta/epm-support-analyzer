import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import closing
from collections import defaultdict
from typing import Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rules import PROCMON_RESULTS, compiled

TEXT_EXT = {".log", ".txt", ".out", ".err", ".csv", ".xml", ".json", ".conf", ".cfg", ".ini", ""}
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})|(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?: ?[AP]M)?)|([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})")
MAX_TEXT_LIST = 20


class Package:
    def __init__(self, path: str):
        self.path = path
        self.kind = "dir" if os.path.isdir(path) else ("zip" if zipfile.is_zipfile(path) else "tar")
        if self.kind == "zip":
            self.zf = zipfile.ZipFile(path)
        elif self.kind == "tar":
            self.tf = tarfile.open(path)

    def close(self):
        if self.kind == "zip":
            self.zf.close()
        elif self.kind == "tar":
            self.tf.close()

    def names(self) -> List[str]:
        if self.kind == "dir":
            out = []
            for root, dirs, files in os.walk(self.path):
                for d in dirs:
                    if d.endswith(".logarchive"):
                        out.append(os.path.relpath(os.path.join(root, d), self.path).replace(os.sep, "/") + "/")
                for f in files:
                    out.append(os.path.relpath(os.path.join(root, f), self.path).replace(os.sep, "/"))
            return sorted(out)
        if self.kind == "zip":
            return [n for n in self.zf.namelist() if not n.endswith("/") or ".logarchive" in n]
        return [m.name for m in self.tf.getmembers() if m.isfile()]

    def open(self, name: str):
        if self.kind == "dir":
            return open(os.path.join(self.path, name), "rb")
        if self.kind == "zip":
            return self.zf.open(name)
        return self.tf.extractfile(name)

    def read(self, name: str) -> bytes:
        with self.open(name) as f:
            return f.read()


def detect_encoding(head: bytes) -> Optional[str]:
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if len(head) > 3 and head[1:2] == b"\x00" and head[3:4] == b"\x00":
        return "utf-16-le"
    if b"\x00" in head:
        return None
    try:
        head.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        if e.start > len(head) - 4:
            return "utf-8"
        return "cp1252"


def iter_lines(raw, enc: str) -> Iterator[Tuple[int, str]]:
    with io.TextIOWrapper(raw, encoding=enc, errors="replace", newline="") as text:
        n = 0
        pending = ""
        for chunk in iter(lambda: text.read(65536), ""):
            pending += chunk
            hold = pending.endswith("\r")
            if hold:
                pending = pending[:-1]
            parts = re.split(r"\r\n|\n|\r", pending)
            pending = parts.pop() + ("\r" if hold else "")
            for p in parts:
                n += 1
                yield n, p
        pending = pending.rstrip("\r")
        if pending:
            n += 1
            yield n, pending


def detect_platform(names: List[str]) -> str:
    low = " ".join(names).lower()
    score = {
        "windows": sum(low.count(k) for k in (".evtx", ".pml", "programdata", "windows", "vfagent", "registry", ".reg")),
        "macos": sum(low.count(k) for k in (".logarchive", "library/", "system.log", "install.log", ".plist", "macos", "darwin")),
        "linux": sum(low.count(k) for k in ("var/log", "syslog", "journal", "messages", "/etc/", "linux", "dmesg")),
    }
    best = max(score, key=score.get)
    return best if score[best] else "unknown"


class Report:
    def __init__(self, source: str, platform: str):
        self.source = source
        self.platform = platform
        self.hits: Dict[str, Dict[str, List[Tuple[int, Optional[str], str]]]] = defaultdict(lambda: defaultdict(list))
        self.severity: Dict[str, str] = {}
        self.scanned: List[str] = []
        self.skipped: List[Tuple[str, str]] = []
        self.notes: List[str] = []

    def add(self, cat, sev, path, line, text):
        m = TS_RE.search(text)
        self.severity[cat] = sev
        self.hits[cat][path].append((line, m.group(0) if m else None, text.strip()[:300]))


def scan_text(rep: Report, pkg: Package, name: str, rules, label: Optional[str] = None, raw=None):
    label = label or name
    fh = raw or pkg.open(name)
    head = fh.peek(4096)[:4096] if hasattr(fh, "peek") else None
    if head is None:
        with fh:
            data = fh.read()
        fh = io.BufferedReader(io.BytesIO(data))
        head = data[:4096]
    enc = detect_encoding(head)
    if enc is None:
        rep.skipped.append((label, "binary"))
        fh.close()
        return
    rep.scanned.append(label)
    for n, line in iter_lines(fh, enc):
        for r in rules:
            if r["regex"].search(line):
                rep.add(r["name"], r["severity"], label, n, line)
                break


def is_procmon_csv(pkg: Package, name: str):
    with pkg.open(name) as raw:
        return b"Process Name" in raw.read(4096).replace(b"\x00", b"")


def scan_procmon_csv(rep: Report, pkg: Package, name: str):
    data = pkg.read(name)
    enc = detect_encoding(data[:4096]) or "utf-8"
    text = data.decode(enc, errors="replace")
    rows = csv.reader(io.StringIO(text, newline=""))
    header = next(rows, [])
    idx = {h.strip(): i for i, h in enumerate(header)}
    rep.scanned.append(name)
    for row in rows:
        line = rows.line_num
        res = row[idx["Result"]].strip().upper() if idx.get("Result", 99) < len(row) else ""
        if res in PROCMON_RESULTS:
            proc = row[idx["Process Name"]] if "Process Name" in idx else ""
            p = row[idx["Path"]] if "Path" in idx else ""
            ts = row[idx["Time of Day"]] if "Time of Day" in idx else None
            rep.severity["Procmon: " + res] = "medium"
            rep.hits["Procmon: " + res][name].append((line, ts, f"{proc} {p}"[:300]))


def scan_evtx(rep: Report, pkg: Package, name: str, rules):
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        rep.skipped.append((name, "evtx found but python-evtx not installed (pip install python-evtx)"))
        return
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as t:
        t.write(pkg.read(name))
    try:
        rep.scanned.append(name)
        with evtx.Evtx(t.name) as log:
            for i, rec in enumerate(log.records(), 1):
                xml = rec.xml()
                lvl = re.search(r"<Level>(\d)</Level>", xml)
                if lvl and lvl.group(1) in ("1", "2"):
                    rep.add("Event Viewer: Critical/Error", "high", name + " (record #)", i, xml[:300])
                for r in rules[:-1]:
                    if r["regex"].search(xml):
                        rep.add(r["name"], r["severity"], name + " (record #)", i, xml[:300])
                        break
    finally:
        os.unlink(t.name)


def scan_logarchive(rep: Report, pkg: Package, name: str, rules):
    if sys.platform != "darwin" or not shutil.which("log"):
        rep.skipped.append((name, "macOS unified log archive: parsing requires macOS and the 'log' tool"))
        return
    tmp = tempfile.mkdtemp()
    try:
        if pkg.kind == "dir":
            arch = os.path.join(pkg.path, name)
        else:
            for n in pkg.names():
                if n.startswith(name) and not n.endswith("/"):
                    dest = os.path.realpath(os.path.join(tmp, n))
                    if os.path.commonpath([os.path.realpath(tmp), dest]) != os.path.realpath(tmp):
                        raise ValueError("Archive contains an unsafe path")
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as f:
                        f.write(pkg.read(n))
            arch = os.path.join(tmp, name)
        out = subprocess.run(["log", "show", "--style", "compact", "--archive", arch],
                             capture_output=True, timeout=1800)
        label = name.rstrip("/") + " (log show output)"
        rep.notes.append(f"Line numbers for {label} refer to the output of 'log show --style compact --archive'.")
        scan_text(rep, pkg, name, rules, label=label, raw=io.BufferedReader(io.BytesIO(out.stdout)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_journal(rep: Report, pkg: Package, name: str, rules):
    if not shutil.which("journalctl"):
        rep.skipped.append((name, "systemd journal file: requires journalctl"))
        return
    with tempfile.NamedTemporaryFile(suffix=".journal", delete=False) as t:
        t.write(pkg.read(name))
    try:
        out = subprocess.run(["journalctl", "--no-pager", "--file", t.name], capture_output=True, timeout=1800)
        label = name + " (journalctl output)"
        rep.notes.append(f"Line numbers for {label} refer to the output of 'journalctl --file'.")
        scan_text(rep, pkg, name, rules, label=label, raw=io.BufferedReader(io.BytesIO(out.stdout)))
    finally:
        os.unlink(t.name)


def scan_package(pkg: Package, platform: str, rep: Report, prefix: str = "", depth: int = 0):
    rules = compiled(platform)
    archives_done = set()
    for name in pkg.names():
        label = prefix + name
        low = name.lower()
        if ".logarchive" in low:
            root = name[: low.index(".logarchive") + len(".logarchive")] + "/"
            if root not in archives_done:
                archives_done.add(root)
                scan_logarchive(rep, pkg, root, rules)
            continue
        ext = os.path.splitext(low)[1]
        if ext in (".zip", ".tar", ".gz", ".tgz") and depth < 3:
            data = pkg.read(name)
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as t:
                t.write(data)
            try:
                if zipfile.is_zipfile(t.name) or tarfile.is_tarfile(t.name):
                    with closing(Package(t.name)) as nested:
                        scan_package(nested, platform, rep, label + "/", depth + 1)
                else:
                    rep.skipped.append((label, "unreadable archive"))
            finally:
                os.unlink(t.name)
        elif ext == ".evtx":
            scan_evtx(rep, pkg, name, rules)
        elif ext == ".pml":
            rep.skipped.append((label, "Procmon PML is binary: open in Procmon and export to CSV, then re-run"))
        elif ext == ".journal":
            scan_journal(rep, pkg, name, rules)
        elif ext == ".csv" and is_procmon_csv(pkg, name):
            scan_procmon_csv(rep, pkg, name)
            _relabel(rep, name, label)
        elif ext in TEXT_EXT or re.search(r"\.log\.\d+$|\.\d+$", low):
            scan_text(rep, pkg, name, rules, label=label)
        else:
            rep.skipped.append((label, "not a log type"))


def _relabel(rep, name, label):
    if name == label:
        return
    rep.scanned = [label if s == name else s for s in rep.scanned]
    for files in rep.hits.values():
        if name in files:
            files[label] = files.pop(name)


def ranges(nums: List[int]) -> List[str]:
    out, nums = [], sorted(set(nums))
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else f"{nums[i]}-{nums[j]}")
        i = j + 1
    return out


def summary(rep: Report):
    cats = []
    for cat, files in rep.hits.items():
        total = sum(len(v) for v in files.values())
        flist = []
        for path, hits in sorted(files.items(), key=lambda kv: -len(kv[1])):
            ts = [h[1] for h in hits if h[1]]
            flist.append({"path": path, "count": len(hits), "lines": [h[0] for h in hits],
                          "line_ranges": ranges([h[0] for h in hits]),
                          "first_timestamp": ts[0] if ts else None, "last_timestamp": ts[-1] if ts else None,
                          "samples": [{"line": h[0], "text": h[2]} for h in hits]})
        cats.append({"category": cat, "severity": rep.severity.get(cat, ""), "total": total, "files": flist})
    cats.sort(key=lambda c: -c["total"])
    return cats


def write_text(rep, cats, md=False):
    o = []
    h = (lambda s: f"## {s}") if md else (lambda s: f"\n{s}\n" + "-" * len(s))
    o.append("# EPM support info error report" if md else "EPM support info error report")
    o.append(f"Source: {rep.source}\nPlatform: {rep.platform}\nFiles scanned: {len(rep.scanned)}\nFiles skipped: {len(rep.skipped)}")
    o.append("Note: rules are starter patterns, to be tuned with real samples.")
    o.append(h("Summary"))
    if md:
        o.append("| Category | Severity | Count |\n|---|---|---|")
    for c in cats:
        o.append(f"| {c['category']} | {c['severity']} | {c['total']} |" if md else f"{c['total']:>8}  {c['severity']:<7} {c['category']}")
    for c in cats:
        o.append(h(f"{c['category']} ({c['total']})"))
        for f in c["files"]:
            r = f["line_ranges"]
            shown = ", ".join(r[:MAX_TEXT_LIST]) + (f" and {len(r) - MAX_TEXT_LIST} more" if len(r) > MAX_TEXT_LIST else "")
            ts = f"  [{f['first_timestamp']} .. {f['last_timestamp']}]" if f["first_timestamp"] else ""
            o.append(f"{'- ' if md else '  '}{f['path']}: {f['count']}{ts}\n{'  ' if md else '    '}lines: {shown}")
    if rep.skipped:
        o.append(h("Skipped files"))
        o += [f"{'- ' if md else '  '}{p}: {why}" for p, why in rep.skipped]
    if rep.notes:
        o.append(h("Notes"))
        o += [f"{'- ' if md else '  '}{n}" for n in rep.notes]
    return "\n".join(o) + "\n"


def report_dict(rep, cats):
    return {"source": rep.source, "platform": rep.platform, "files_scanned": rep.scanned,
            "files_skipped": [{"path": p, "reason": r} for p, r in rep.skipped],
            "notes": rep.notes, "categories": cats}


def render(rep, cats, fmt):
    if fmt == "json":
        return json.dumps(report_dict(rep, cats), indent=2)
    if fmt == "csv":
        s = io.StringIO()
        w = csv.writer(s)
        w.writerow(["category", "severity", "path", "line", "text"])
        for c in cats:
            for f in c["files"]:
                for smp in f["samples"]:
                    w.writerow([c["category"], c["severity"], f["path"], smp["line"], smp["text"]])
        return s.getvalue()
    return write_text(rep, cats, md=(fmt == "md"))



def run(path: str, platform: str = "auto") -> Tuple[Report, list]:
    with closing(Package(path)) as pkg:
        plat = detect_platform(pkg.names()) if platform == "auto" else platform
        rep = Report(path, plat)
        scan_package(pkg, plat, rep)
        return rep, summary(rep)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Count error instances in a decrypted EPM support info package.")
    ap.add_argument("package", help="support info .zip, .tar, .tar.gz, or an extracted folder")
    ap.add_argument("--platform", choices=["auto", "windows", "macos", "linux"], default="auto")
    ap.add_argument("--output", "-o", help="report file (.txt, .md, .json, .csv); prints to screen if omitted")
    ap.add_argument("--context", type=int, default=0, help="include N matching sample lines per file in the text report")
    a = ap.parse_args(argv)
    rep, cats = run(a.package, a.platform)
    fmt = os.path.splitext(a.output)[1].lstrip(".").lower() if a.output else "txt"
    out = render(rep, cats, fmt if fmt in ("json", "csv", "md") else "txt")
    if a.context and fmt in ("txt", "md", ""):
        extra = ["\nSample lines"]
        for c in cats:
            for f in c["files"]:
                for smp in f["samples"][: a.context]:
                    extra.append(f"  [{c['category']}] {f['path']}:{smp['line']}: {smp['text']}")
        out += "\n".join(extra) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8", newline="") as f:
            f.write(out)
        print(f"Report written to {a.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
