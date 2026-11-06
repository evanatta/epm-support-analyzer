import http.client
import io
import tarfile
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import epm_support_report as report
import server
from make_sample import build


def multipart(data=b"", filename="support-info.zip", platform="auto", include_file=True):
    boundary = "epm-test-boundary"
    parts = []
    if include_file:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                      'Content-Type: application/octet-stream\r\n\r\n').encode() + data + b"\r\n")
    if platform is not None:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="platform"\r\n\r\n'
                      f'{platform}\r\n').encode())
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), {"Content-Type": "multipart/form-data; boundary=" + boundary}


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.sample_path = build(os.path.join(cls.tmp.name, "sample.zip"))
        cls.sample = Path(cls.sample_path).read_bytes()
        cls.httpd = server.LocalServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def upload(self, **kwargs):
        body, headers = multipart(**kwargs)
        status, response_headers, response = self.request("POST", "/api/analyze", body, headers)
        return status, response_headers, json.loads(response)

    def test_health(self):
        status, headers, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_sample_upload_matches_cli(self):
        paths = []
        real_run = server.run

        def tracking_run(path, platform):
            paths.append(path)
            self.assertTrue(os.path.isfile(path))
            return real_run(path, platform)

        with patch.object(server, "run", side_effect=tracking_run):
            status, _, data = self.upload(data=self.sample)
        self.assertEqual(status, 200)
        self.assertEqual(data["source"], "support-info.zip")
        self.assertEqual(data["platform"], "windows")
        categories = {category["category"] for category in data["categories"]}
        self.assertIn("MQTT communication errors", categories)
        self.assertIn("TLS/certificate errors", categories)
        rep, cats = report.run(self.sample_path)
        rep.source = "support-info.zip"
        self.assertEqual(data, json.loads(report.render(rep, cats, "json")))
        self.assertEqual(len(paths), 1)
        self.assertFalse(os.path.exists(paths[0]))
        self.assertNotIn(paths[0], json.dumps(data))
        self.assertNotIn("epm-upload-", json.dumps(data))

    def test_optional_platform(self):
        status, _, data = self.upload(data=self.sample, platform=None)
        self.assertEqual(status, 200)
        self.assertEqual(data["platform"], "windows")

    def test_platform_override(self):
        status, _, data = self.upload(data=self.sample, platform="linux")
        self.assertEqual(status, 200)
        self.assertEqual(data["platform"], "linux")

    def test_missing_file(self):
        status, _, data = self.upload(include_file=False)
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_empty_file(self):
        self.assertEqual(self.upload(data=b"")[0], 400)

    def test_invalid_platform(self):
        self.assertEqual(self.upload(data=self.sample, platform="invalid")[0], 400)

    def test_invalid_extension(self):
        self.assertEqual(self.upload(data=self.sample, filename="support-info.txt")[0], 400)

    def test_bad_archive_and_cleanup(self):
        paths = []

        def broken_run(path, platform):
            paths.append(path)
            raise ValueError(path)

        with patch.object(server, "run", side_effect=broken_run):
            status, _, data = self.upload(data=b"invalid archive")
        self.assertEqual(status, 400)
        self.assertNotIn(paths[0], json.dumps(data))
        self.assertFalse(os.path.exists(paths[0]))
        self.assertFalse(server.ANALYSIS_LOCK.locked())

    def test_damaged_archive(self):
        self.assertEqual(self.upload(data=b"invalid archive")[0], 400)

    def test_oversize(self):
        with patch.object(server, "MAX_UPLOAD", 32):
            self.assertEqual(self.upload(data=self.sample)[0], 413)

    def test_multipart_required(self):
        status, _, _ = self.request("POST", "/api/analyze", b"{}", {"Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_incomplete_multipart(self):
        body, headers = multipart(data=self.sample)
        status, _, _ = self.request("POST", "/api/analyze", body.rsplit(b"--epm-test-boundary--", 1)[0], headers)
        self.assertEqual(status, 400)

    def test_local_cors(self):
        status, headers, _ = self.request("OPTIONS", "/api/analyze", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "http://localhost:5173")
        self.assertIn("POST", headers["Access-Control-Allow-Methods"])

    def test_external_origin_rejected(self):
        status, headers, _ = self.request("POST", "/api/analyze", headers={"Origin": "https://example.invalid"})
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_external_host_rejected(self):
        status, _, _ = self.request("GET", "/api/health", headers={"Host": "example.invalid"})
        self.assertEqual(status, 403)

    def test_concurrent_analysis_rejected(self):
        with server.ANALYSIS_LOCK:
            self.assertEqual(self.upload(data=self.sample)[0], 503)

    def test_built_frontend_and_route(self):
        dist = Path(self.tmp.name) / "dist"
        dist.mkdir(exist_ok=True)
        (dist / "index.html").write_text("<html>Support Info</html>")
        (dist / "app.js").write_text("const value = 1")
        with patch.object(server, "DIST", dist):
            for path in ("/", "/tools/support-info"):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn("text/html", headers["Content-Type"])
                self.assertIn(b"Support Info", body)
            status, headers, _ = self.request("GET", "/app.js")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "text/javascript")
            self.assertEqual(self.request("GET", "/%2e%2e/README.md")[0], 404)
            self.assertEqual(self.request("GET", "/api/missing")[0], 404)

    def test_tar_and_compressed_tar(self):
        for mode, filename in (("w", "support-info.tar"), ("w:gz", "support-info.tar.gz")):
            with self.subTest(filename=filename):
                archive = io.BytesIO()
                line = b"2026-01-01 10:00:05 ERROR MQTT connection lost\n"
                with tarfile.open(fileobj=archive, mode=mode) as tar:
                    member = tarfile.TarInfo("var/log/syslog")
                    member.size = len(line)
                    tar.addfile(member, io.BytesIO(line))
                status, _, data = self.upload(data=archive.getvalue(), filename=filename)
                self.assertEqual(status, 200)
                self.assertEqual(data["source"], filename)
                self.assertEqual(data["platform"], "linux")
                self.assertEqual(data["categories"][0]["category"], "MQTT communication errors")

    def test_filename_path_is_removed(self):
        status, _, data = self.upload(data=self.sample, filename="/uploads/support-info.zip")
        self.assertEqual(status, 200)
        self.assertEqual(data["source"], "support-info.zip")

    def test_duplicate_file_field(self):
        body, headers = multipart(data=self.sample)
        duplicate = body.rsplit(b"--epm-test-boundary--", 1)[0] + body
        self.assertEqual(self.request("POST", "/api/analyze", duplicate, headers)[0], 400)

    def test_missing_boundary(self):
        self.assertEqual(self.request("POST", "/api/analyze", b"test", {"Content-Type": "multipart/form-data"})[0], 400)

    def test_invalid_length(self):
        self.assertEqual(self.request("POST", "/api/analyze", headers={"Content-Length": "invalid"})[0], 400)

    def test_empty_request(self):
        self.assertEqual(self.request("POST", "/api/analyze")[0], 400)

    def test_api_without_frontend(self):
        with patch.object(server, "DIST", Path(self.tmp.name) / "missing"):
            self.assertEqual(self.request("GET", "/api/health")[0], 200)
            self.assertEqual(self.request("GET", "/")[0], 404)


if __name__ == "__main__":
    unittest.main()
