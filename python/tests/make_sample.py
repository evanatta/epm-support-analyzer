import gzip
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


def _stamp(day, n, sep="."):
    return f"2026{sep}01{sep}0{day} 10:00:0{n}"


def build_windows(path: str) -> str:
    t = lambda n: f"{_stamp(2, n)} PID:100 TID:200 "
    srv = "\r\n".join([
        t(0) + "CvfAgentMain::Init: INFO: started",
        t(1) + "CvfAwsIotComm::AWS_COM_KIT: sck: Failed to send message 1 'x': client is not connected.",
        t(2) + "CvfAwsIotComm::AWS_COM_KIT: http-connection: Client shutdown completed with error 2 (AWS_ERROR_HTTP_PROXY_CONNECT_FAILED).",
        t(3) + "CvfScriptTargetUtil::_PowerShellRecognizePermittedPattern: ERROR: Missing policy section terminator",
        t(4) + "CvfPolicy::PolicyFromXML: ERROR: Failed to load policy 7 [Fake Policy] (NORMAL_RUN) from XML. Policy skipped.",
        t(5) + "CvfAgentMain::_AcquirePrivileges: VF_AGENT runs with ORIGINAL token, PM is disabled, no elevation.",
        t(6) + "CvfDrvMngr::_ReleaseWaitInKernel: DRV ERROR: SendMessageToPort (ReleaseWait) failed. LastError=6",
        t(7) + "CvfAwsIotComm::AWS_COM_KIT: sck: Received PUBACK (packet_id: 1, reason: 0 'Success', error: 'aws-c-common: AWS_ERROR_SUCCESS, Success.').",
    ]) + "\r\n"
    rotated = f"{_stamp(1, 0)} PID:100 TID:201 CvfSecureIPCHelper::StartAgentConnection: ERROR: No connection from agent.; Server Name = [fakeServ]\r\n"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("trace/vf_agent_srv.trace", srv.encode("utf-8"))
        z.writestr("trace/vf_agent_srv.trace.1", rotated)
        z.writestr("trace/vf_host.x64.{1}.trace", t(0) + "CvfHost::Run: INFO: " + FAKE + "\r\n")
        z.writestr("trace/restart.txt", "Stopped Fri 01/02/2026 10:00:00.00\r\nAttempt 1: start Fri 01/02/2026 10:00:05.00\r\n")
    return path


def build_linux(path: str) -> str:
    log = lambda n, lvl, msg: f"{_stamp(2, n, '-')}.000001Z  {lvl}  M0000000{n}  [P1:G1]  {msg}\n"
    root = "epm-supportinfo-fake/"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(root + "initialInfo", "Agent version: 1.0.0.1\nLatest status: EPM Agent is not running\nAgent Services: disconnected\n")
        z.writestr(root + "epm.log",
                   log(0, "INFO", "Latest status: starting")
                   + log(1, "ERROR", "NSS: user #1001: timeout")
                   + log(2, "WARN", "NSS: user fake-user-01: policy #1 'p': can't resolve user fake-user-01: RESOLVE: user fake-user-01: not found")
                   + log(3, "ERROR", "TG: #1: VfAgntWebClnt: GetManagerAddressEx call failed with error: 'x': 'y'")
                   + log(4, "INFO", "ASC: sck: Received incoming message (id: 1 'x', correlation data: 'y', error: 0 '').")
                   + log(5, "DEBUG", "ASC: mqtt5-client: id=0x1: dynamic ping timeout: 100 ns"))
        z.writestr(root + "epm.log.1.gz", gzip.compress(
            log(4, "INFO", "ok").encode()
            + log(5, "ERROR", "NSS: group #1: NG client #1: fetch group: ASC: sck: Failed to fetch a details of a group 'g' (1): EPM_RESULT_ERR_TIMEOUT.").encode()))
        z.writestr(root + "epm.log.2.gz", b"\x1f\x8bnot gzip")
        z.writestr(root + "sysSudo/epmsudo.log-20260101",
                   f"Jan  1 10:00:00 {FAKE} epmsudo[10]: 2026/01/01 10:00:00.000 E 10 |epm-sudo| can't list privileges: the sudoers plugin has failed to list privileges\n")
        z.writestr(root + "messages",
                   f"Jan  1 10:00:00 {FAKE} crond[5]: (root) PAM ERROR (Authentication token is no longer valid; new one required)\n"
                   f"Jan  1 10:00:01 {FAKE} sshd[7]: |epm-nss| |7:7| Can't connect to the EPM agent: socket - connect: Connection refused\n")
    return path


def build_macos(path: str) -> str:
    root = "CyberArkEPMSupportInfo_fake/"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(root + "epm_status.txt",
                   "Version:                    1.0.0.1\n"
                   "Full Disk Access:           Not Granted\n"
                   "Network Extension:          Approved\n"
                   "Network Filter:             Enabled\n"
                   "Server Connection:          Not established (disconnect reason: \"fake\")\n"
                   "Server Connection (Beta):   Established\n"
                   "Policy Suspended:           No\n")
        z.writestr(root + "system_diagnostics/systemextensionsctl_list.txt",
                   "*\t*\tFAKETEAM01\tcom.cyberark.FakeExtension (1.0/1)\tFake Extension\t[activated enabled]\n"
                   "\t\tFAKETEAM01\tcom.cyberark.FakeExtension (0.9/1)\tFake Extension\t[terminated waiting to uninstall on reboot]\n")
        z.writestr(root + "system_diagnostics/spindump.txt", "  1  -[FakeDatabase runQuery:onError:] + 10\n")
        z.writestr(root + "logs/logs_last_1d_only_epm_errors.log",
                   "2026-01-02 10:00:00.000 E  fakeagent[1:2] [fake:ServerCommunication] [channel-bootstrap] id=0x1: "
                   "Connection failed with error_code 1048 : AWS_IO_SOCKET_TIMEOUT.\n")
    return path


if __name__ == "__main__":
    print(build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), "sample_support_info.zip")))
