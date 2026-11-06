import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import epm_support_report as r
from make_sample import build, build_linux, build_macos, build_windows


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


def lines_for(cats, name, path):
    return files_for(cats, name).get(path, {}).get("lines")


class EpmRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.win = r.run(build_windows(os.path.join(cls.tmp, "win.zip")))
        cls.lnx = r.run(build_linux(os.path.join(cls.tmp, "lnx.zip")))
        cls.mac = r.run(build_macos(os.path.join(cls.tmp, "mac.zip")))

    def test_platforms(self):
        self.assertEqual(self.win[0].platform, "windows")
        self.assertEqual(self.lnx[0].platform, "linux")
        self.assertEqual(self.mac[0].platform, "macos")

    def test_windows_trace_rules(self):
        cats = self.win[1]
        log = "trace/vf_agent_srv.trace"
        self.assertEqual(lines_for(cats, "EPM cloud client not connected", log), [2])
        self.assertEqual(lines_for(cats, "EPM proxy connection failures", log), [3])
        self.assertEqual(lines_for(cats, "Policy section terminator missing", log), [4])
        self.assertEqual(lines_for(cats, "Policy load/parse failures", log), [5])
        self.assertEqual(lines_for(cats, "Privilege management disabled", log), [6])
        self.assertEqual(lines_for(cats, "Agent driver communication errors", log), [7])
        self.assertEqual(lines_for(cats, "Agent IPC failures", "trace/vf_agent_srv.trace.1"), [1])
        self.assertEqual(lines_for(cats, "Agent service restarts", "trace/restart.txt"), [1, 2])
        self.assertEqual(files_for(cats, "EPM proxy connection failures")[log]["first_timestamp"], "2026.01.02 10:00:02")

    def test_benign_lines_ignored(self):
        hits = [l for c in self.win[1] for f in c["files"] if f["path"] == "trace/vf_agent_srv.trace" for l in f["lines"]]
        self.assertNotIn(8, hits)
        self.assertNotIn(1, hits)

    def test_linux_rules(self):
        rep, cats = self.lnx
        root = "epm-supportinfo-fake/"
        self.assertEqual(lines_for(cats, "Agent not running", root + "initialInfo"), [2])
        self.assertEqual(lines_for(cats, "Agent not connected to EPM server", root + "initialInfo"), [3])
        self.assertEqual(lines_for(cats, "User/group resolution timeouts", root + "epm.log"), [2])
        self.assertEqual(lines_for(cats, "User/group not found", root + "epm.log"), [3])
        self.assertEqual(lines_for(cats, "EPM manager address unreachable", root + "epm.log"), [4])
        self.assertEqual(lines_for(cats, "EPM server request errors", root + "epm.log.1.gz"), [2])
        self.assertEqual(lines_for(cats, "EPM sudo plugin failures", root + "sysSudo/epmsudo.log-20260101"), [1])
        self.assertEqual(lines_for(cats, "Expired account passwords", root + "messages"), [1])
        self.assertEqual(lines_for(cats, "PAM/NSS modules cannot reach the agent", root + "messages"), [2])
        hits = [l for c in cats for f in c["files"] if f["path"] == root + "epm.log" for l in f["lines"]]
        self.assertEqual(sorted(hits), [2, 3, 4])
        self.assertIsNone(lines_for(cats, "Agent not running", root + "epm.log"))
        self.assertIn(root + "epm.log.1.gz", rep.scanned)
        self.assertIn(root + "epm.log.2.gz", dict(rep.skipped))

    def test_macos_status_rules(self):
        cats = self.mac[1]
        root = "CyberArkEPMSupportInfo_fake/"
        self.assertEqual(lines_for(cats, "macOS agent permissions missing", root + "epm_status.txt"), [2])
        self.assertEqual(lines_for(cats, "Agent not connected to EPM server", root + "epm_status.txt"), [5])
        self.assertEqual(lines_for(cats, "macOS system extension not active", root + "system_diagnostics/systemextensionsctl_list.txt"), [2])
        self.assertEqual(lines_for(cats, "EPM socket timeouts and drops", root + "logs/logs_last_1d_only_epm_errors.log"), [1])
        self.assertEqual(files_for(cats, "Policy enforcement suspended"), {})
        self.assertIn(root + "system_diagnostics/spindump.txt", dict(self.mac[0].skipped))

    def test_impacts(self):
        cats = self.win[1]
        cat = next(c for c in cats if c["category"] == "EPM proxy connection failures")
        self.assertEqual(cat["impact"], "Server connectivity")
        self.assertTrue(cat["description"])
        groups = {g["impact"]: g for g in r.impacts(cats)}
        self.assertEqual(groups["Server connectivity"]["severity"], "high")
        self.assertEqual(groups["Policy delivery and enforcement"]["total"], 3)
        self.assertEqual(r.impacts(cats)[0]["severity"], "high")
        data = json.loads(r.render(self.win[0], cats, "json"))
        self.assertEqual(data["impacts"], r.impacts(cats))
        self.assertIn("Impact areas", r.render(self.win[0], cats, "txt"))
        self.assertTrue(r.render(self.win[0], cats, "csv").startswith("category,severity,path,line,text,impact"))


if __name__ == "__main__":
    unittest.main()
