import re

ALL = ("windows", "macos", "linux")

GENERIC_RULES = [
    {"name": "MQTT communication errors", "severity": "high", "platforms": ALL,
     "pattern": r"mqtt.*(error|fail|lost|refused|timeout|timed out|disconnect|unable)|(error|fail|lost|refused|timeout|disconnect|unable).*mqtt"},
    {"name": "Server/HTTPS communication failures", "severity": "high", "platforms": ALL,
     "pattern": r"(https?|dispatcher|server|connection).*(fail|refused|unreachable|timed out|timeout|reset|status code 5\d\d)"},
    {"name": "TLS/certificate errors", "severity": "high", "platforms": ALL,
     "pattern": r"(ssl|tls|certificate|x509|handshake).*(error|fail|invalid|expired|untrusted|revoked)"},
    {"name": "DNS resolution failures", "severity": "medium", "platforms": ALL,
     "pattern": r"(dns|resolve|host ?name|getaddrinfo).*(fail|error|not found|unknown)|name or service not known|no such host"},
    {"name": "Proxy errors", "severity": "medium", "platforms": ALL,
     "pattern": r"proxy.*(error|fail|refused|auth|407)"},
    {"name": "Policy download/parse failures", "severity": "high", "platforms": ALL,
     "pattern": r"polic(y|ies).*(fail|error|invalid|corrupt|could not|cannot|unable)"},
    {"name": "Service start failures/crashes", "severity": "high", "platforms": ALL,
     "pattern": r"(service|daemon|agent).*(failed to start|crash|terminated unexpectedly|stopped unexpectedly|core dump|segfault)|segmentation fault"},
    {"name": "Driver/kernel extension load errors", "severity": "high", "platforms": ALL,
     "pattern": r"(driver|minifilter|filter manager|kext|system extension|kernel module).*(fail|error|not loaded|could not|denied)"},
    {"name": "Access denied", "severity": "medium", "platforms": ALL,
     "pattern": r"access (is )?denied|permission denied|operation not permitted|0x80070005"},
    {"name": "Disk/database errors", "severity": "medium", "platforms": ALL,
     "pattern": r"sqlite.*(error|fail|corrupt|locked)|database (is )?(locked|corrupt|malformed)|disk (is )?full|no space left"},
    {"name": "License/registration errors", "severity": "high", "platforms": ALL,
     "pattern": r"(licen[cs]e|registration|register|enroll).*(fail|error|invalid|expired|denied)"},
    {"name": "Generic ERROR/FATAL/Exception", "severity": "low", "platforms": ALL,
     "pattern": r"\b(error|fatal|critical)\b|exception"},
]

EPM_SPECIFIC_RULES = [
]

RULES = GENERIC_RULES + EPM_SPECIFIC_RULES

PROCMON_RESULTS = ["ACCESS DENIED", "NAME NOT FOUND", "PATH NOT FOUND", "SHARING VIOLATION",
                   "NAME COLLISION", "INVALID PARAMETER", "PRIVILEGE NOT HELD", "BAD NETWORK PATH"]


def compiled(platform):
    out = []
    for r in RULES:
        if platform in r["platforms"] or platform == "unknown":
            out.append(dict(r, regex=re.compile(r["pattern"], re.IGNORECASE)))
    return out
