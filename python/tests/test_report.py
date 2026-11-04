import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import epm_support_report as r
from make_sample import build


def files_for(cats, name):
    for c in cats:
        if c["category"] == name:
            return {f["path"]: f for f in c["files"]}
    return {}


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.zip = build(os.path.join(cls.tmp, "sample.zip"))
        cls.rep, cls.cats = r.run(cls.zip)

    def test_platform(self):
        self.assertEqual(self.rep.platform, "windows")

    def test_crlf_line_numbers(self):
        f = files_for(self.cats, "MQTT communication errors")["ProgramData/Agent/Logs/agent.log"]
        self.assertEqual(f["lines"], [2, 3])
        self.assertEqual(f["line_ranges"], ["2-3"])
        self.assertEqual(f["first_timestamp"], "2026-01-01 09:00:01")
        tls = files_for(self.cats, "TLS/certificate errors")["ProgramData/Agent/Logs/agent.log"]
        self.assertEqual(tls["lines"], [5])

    def test_utf16(self):
        f = files_for(self.cats, "MQTT communication errors")["ProgramData/Agent/Logs/utf16.log"]
        self.assertEqual(f["lines"], [3])

    def test_cp1252(self):
        f = files_for(self.cats, "Access denied")["ProgramData/Agent/Logs/cp1252.log"]
        self.assertEqual(f["lines"], [2])

    def test_nested_zip(self):
        f = files_for(self.cats, "MQTT communication errors")
        self.assertEqual(f["nested/inner.zip/Logs/nested_agent.log"]["lines"], [2])

    def test_procmon_csv(self):
        self.assertEqual(files_for(self.cats, "Procmon: ACCESS DENIED")["Procmon/procmon.csv"]["lines"], [3])
        self.assertEqual(files_for(self.cats, "Procmon: NAME NOT FOUND")["Procmon/procmon.csv"]["lines"], [4])

    def test_skipped(self):
        reasons = dict(self.rep.skipped)
        self.assertIn("Procmon/capture.pml", reasons)
        self.assertIn("bin/blob.dat", reasons)
        self.assertTrue(any("evtx" in k for k in reasons))

    def test_ranges(self):
        self.assertEqual(r.ranges([1, 2, 3, 7, 9, 10]), ["1-3", "7", "9-10"])

    def test_outputs(self):
        for ext in ("txt", "md", "json", "csv"):
            out = os.path.join(self.tmp, "report." + ext)
            r.main([self.zip, "-o", out, "--context", "1"])
            self.assertGreater(os.path.getsize(out), 0)
        with open(os.path.join(self.tmp, "report.json")) as fh:
            data = json.load(fh)
        self.assertTrue(data["categories"])

    def test_folder_input(self):
        d = os.path.join(self.tmp, "folder")
        os.makedirs(os.path.join(d, "var/log"))
        with open(os.path.join(d, "var/log/syslog"), "w", newline="") as f:
            f.write("a\nb\nmqtt client disconnected with error\n")
        rep, cats = r.run(d)
        self.assertEqual(rep.platform, "linux")
        self.assertEqual(files_for(cats, "MQTT communication errors")["var/log/syslog"]["lines"], [3])

    def test_chunk_boundary_crlf(self):
        import io
        data = ("x" * 65535 + "\r\n" + "y\r\nz").encode()
        lines = list(r.iter_lines(io.BufferedReader(io.BytesIO(data)), "utf-8"))
        self.assertEqual([n for n, _ in lines], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
