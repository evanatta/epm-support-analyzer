import io
import os
import sys
import zipfile

FAKE = "fake-host-0001"


def build(path: str) -> str:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("Logs/nested_agent.log", "2026-01-01 10:00:00 INFO ok\n2026-01-01 10:00:05 ERROR MQTT connection lost\n")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("ProgramData/Agent/Logs/agent.log",
                   "2026-01-01 09:00:00 INFO start\r\n"
                   "2026-01-01 09:00:01 ERROR MQTT connect refused\r\n"
                   "2026-01-01 09:00:02 ERROR MQTT connect refused\r\n"
                   "2026-01-01 09:00:03 INFO idle\r\n"
                   "2026-01-01 09:00:04 WARN TLS handshake failed: certificate expired\r\n")
        z.writestr("ProgramData/Agent/Logs/utf16.log",
                   ("line one\r\nline two\r\nmqtt publish failed on " + FAKE + "\r\n").encode("utf-16"))
        z.writestr("ProgramData/Agent/Logs/cp1252.log", "caf\xe9 ok\nAccess is denied for caf\xe9\n".encode("cp1252"))
        z.writestr("Procmon/procmon.csv",
                   '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\n'
                   '"9:00:00.0 AM","fake.exe","1","CreateFile","C:\\\\fake\\\\a.txt","SUCCESS",""\n'
                   '"9:00:01.0 AM","fake.exe","1","CreateFile","C:\\\\fake\\\\b.txt","ACCESS DENIED",""\n'
                   '"9:00:02.0 AM","fake.exe","1","RegOpenKey","HKLM\\\\Fake","NAME NOT FOUND",""\n')
        z.writestr("Procmon/capture.pml", b"PML_\x00\x01\x02binary")
        z.writestr("EventLogs/Application.evtx", b"ElfFile\x00binary")
        z.writestr("bin/blob.dat", b"\x00\x01\x02\x03")
        z.writestr("nested/inner.zip", inner.getvalue())
    return path


if __name__ == "__main__":
    print(build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), "sample_support_info.zip")))
