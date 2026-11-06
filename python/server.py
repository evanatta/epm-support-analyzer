import argparse
import json
import mimetypes
import os
import socket
import tempfile
import threading
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from epm_support_report import report_dict, run

MAX_UPLOAD = 200 * 1024 * 1024
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
ANALYSIS_LOCK = threading.Lock()


def local_origin(origin):
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme in ("http", "https")
                and parsed.hostname in ("localhost", "127.0.0.1", "::1")
                and parsed.username is None and parsed.password is None
                and parsed.path == "" and not parsed.query and not parsed.fragment
                and (parsed.port is None or 0 < parsed.port < 65536))
    except ValueError:
        return False


class LocalServer(ThreadingHTTPServer):
    daemon_threads = False


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(60)

    def log_message(self, format, *args):
        pass

    def end_headers(self):
        origin = self.headers.get("Origin", "")
        if local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def json_response(self, status, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def allowed(self):
        origin = self.headers.get("Origin")
        try:
            host = urlsplit("http://" + self.headers.get("Host", "")).hostname
        except ValueError:
            host = None
        if host not in ("127.0.0.1", "localhost", "::1") or (origin and not local_origin(origin)):
            self.json_response(403, {"error": "Only local requests are accepted."})
            return False
        return True

    def do_OPTIONS(self):
        if self.allowed():
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        if not self.allowed():
            return
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.json_response(200, {"ok": True})
            return
        if path.startswith("/api/"):
            self.json_response(404, {"error": "Route not found."})
            return
        root = DIST.resolve()
        target = (root / unquote(path).lstrip("/")).resolve()
        if root not in target.parents and target != root:
            self.json_response(404, {"error": "Not found."})
            return
        if path.rstrip("/") in ("", "/tools/support-info"):
            target = root / "index.html"
        if not target.is_file():
            self.json_response(404, {"error": "Frontend not built. Build frontend or use the development server."})
            return
        content = target.read_bytes()
        self.send_response(200)
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix == ".js":
            content_type = "text/javascript"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        if not self.allowed():
            return
        if urlsplit(self.path).path != "/api/analyze":
            self.json_response(404, {"error": "Route not found."})
            return
        if self.headers.get("Transfer-Encoding"):
            self.json_response(400, {"error": "Content-Length is required."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.json_response(400, {"error": "Invalid Content-Length."})
            return
        if length <= 0:
            self.json_response(400, {"error": "Choose a non-empty support-info archive."})
            return
        if length > MAX_UPLOAD:
            self.json_response(413, {"error": "Upload must be smaller than 200 MB including form fields."})
            return
        content_type = self.headers.get("Content-Type", "")
        header = BytesParser(policy=policy.default).parsebytes(
            ("Content-Type: " + content_type + "\r\n\r\n").encode("utf-8"))
        if header.get_content_type() != "multipart/form-data" or not header.get_boundary():
            self.json_response(400, {"error": "Expected a multipart upload."})
            return
        if not ANALYSIS_LOCK.acquire(blocking=False):
            self.json_response(503, {"error": "Another report is running. Try again when it finishes."})
            return
        temp_path = None
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                self.json_response(400, {"error": "Incomplete upload."})
                return
            message = BytesParser(policy=policy.default).parsebytes(
                ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8") + body)
            if not message.is_multipart() or message.defects:
                self.json_response(400, {"error": "Invalid multipart upload."})
                return
            fields = {}
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name not in ("file", "platform") or name in fields or part.is_multipart() or part.defects:
                    self.json_response(400, {"error": "Invalid upload fields."})
                    return
                fields[name] = part
            file = fields.get("file")
            filename = file.get_filename() if file is not None else None
            data = file.get_payload(decode=True) if file is not None else None
            if not filename or not data:
                self.json_response(400, {"error": "Choose a non-empty support-info archive."})
                return
            filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
            if not filename.lower().endswith((".zip", ".tar", ".tar.gz")):
                self.json_response(400, {"error": "Choose a .zip, .tar, or .tar.gz archive."})
                return
            platform = fields["platform"].get_content().strip() if "platform" in fields else "auto"
            if platform not in ("auto", "windows", "macos", "linux"):
                self.json_response(400, {"error": "Invalid platform."})
                return
            with tempfile.NamedTemporaryFile(prefix="epm-upload-", suffix=".archive", delete=False) as tmp:
                temp_path = tmp.name
                tmp.write(data)
            del body, data, message, fields, file
            rep, cats = run(temp_path, platform)
            rep.source = filename
            status, result = 200, report_dict(rep, cats)
        except (socket.timeout, TimeoutError):
            status, result = 408, {"error": "Upload timed out. Try again."}
        except Exception:
            status, result = 400, {"error": "Unable to analyze this archive. Check that it is decrypted and not damaged."}
        finally:
            try:
                if temp_path is not None:
                    os.unlink(temp_path)
            finally:
                ANALYSIS_LOCK.release()
        self.json_response(status, result)


def main():
    parser = argparse.ArgumentParser(description="Serve the local support-info analyzer.")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with LocalServer(("127.0.0.1", args.port), Handler) as server:
        print("EPM Support Analyzer: http://127.0.0.1:" + str(server.server_port), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
