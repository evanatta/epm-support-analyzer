import re

ALL = ("windows", "macos", "linux")
WIN = ("windows",)
MAC = ("macos",)
LNX = ("linux",)

IMPACTS = {
    "connectivity": "Server connectivity",
    "policy": "Policy delivery and enforcement",
    "elevation": "Elevation and sudo",
    "identity": "User and identity resolution",
    "service": "Agent service health",
    "driver": "Driver and system extension",
    "config": "Agent configuration and integrity",
    "auth": "Authentication and sign-in",
    "host": "Host system",
    "general": "General errors",
}

BENIGN = re.compile(r"aws_error_success|sslpolicyerrors=none|errors=0x0\b|error_code 0\b|\berror: 0\b|dynamic ping timeout|timeout (interval )?set to|setting connect timeout|connect_timeout_ms|set to default value|\bevent=accept,")

SNAPSHOT_FILES = re.compile(r"(^|/)(spindump|ps|launchctl_[\w.-]+|pluginkit_[\w.-]+)\.txt$", re.IGNORECASE)

STATUS_RULES = [
    {"name": "Agent not connected to EPM server", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "files": r"(^|/)(initialInfo|epm_status\.txt)$",
     "pattern": r"^\s*server connection:\s*not established|^\s*agent services:\s*(?!connected\s*$)\S",
     "description": "The agent status file reports no working connection to the EPM service, so policies, events, and inventory are not exchanged."},
    {"name": "Agent not running", "severity": "high", "platforms": ALL, "impact": "service",
     "files": r"(^|/)(initialInfo|epm_status\.txt)$",
     "pattern": r"^\s*latest status:\s*(?!epm agent is running\s*$)\S",
     "description": "The agent status file does not report a running agent."},
    {"name": "Policy enforcement suspended", "severity": "high", "platforms": ALL, "impact": "policy",
     "files": r"(^|/)(initialInfo|epm_status\.txt)$",
     "pattern": r"^\s*policy suspended:\s*yes",
     "description": "Policies are suspended on the endpoint and are not enforced."},
    {"name": "macOS agent permissions missing", "severity": "high", "platforms": MAC, "impact": "driver",
     "files": r"(^|/)epm_status\.txt$",
     "pattern": r"^\s*full disk access:\s*(?!granted\s*$)\S|^\s*network extension:\s*(?!approved\s*$)\S|^\s*network filter:\s*(?!enabled\s*$)\S",
     "description": "Full Disk Access, the network extension, or the network filter is not approved or enabled for the agent."},
    {"name": "macOS system extension not active", "severity": "high", "platforms": MAC, "impact": "driver",
     "files": r"(^|/)systemextensionsctl_list\.txt$",
     "pattern": r"(cyberark|epm).*\[(?!activated enabled\])[^\]]+\]\s*$",
     "description": "An agent system extension is waiting for approval, disabled, or pending removal. A reboot or MDM approval may be required."},
    {"name": "Agent service restarts", "severity": "high", "platforms": WIN, "impact": "service",
     "files": r"(^|/)restart\.txt$",
     "pattern": r"^\s*(attempt \d+: start|stopped\b)",
     "description": "The agent service was stopped or restarted. Repeated attempts indicate a restart loop."},
]

EPM_SPECIFIC_RULES = [
    {"name": "Policy section terminator missing", "severity": "high", "platforms": ALL, "impact": "policy",
     "pattern": r"missing policy section terminator",
     "description": "A policy contains a malformed script or pattern section, so the agent cannot evaluate it as intended."},
    {"name": "Policy load/parse failures", "severity": "high", "platforms": ALL, "impact": "policy",
     "pattern": r"failed to load policy|failed to parse targets|policy skipped|unknown target element name|has unknown \S+ attribute value|failed to get applicable policies|getpoliciesapplicableforuser: failed",
     "description": "Policies were skipped or only partly parsed. Applications may not be elevated, blocked, or audited as configured."},
    {"name": "Privilege management disabled", "severity": "high", "platforms": ALL, "impact": "policy",
     "pattern": r"pm is disabled|privilege management is disabled",
     "description": "The agent reports privilege management as disabled, so elevation policies are not applied."},
    {"name": "EPM proxy connection failures", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"aws_error_http_proxy_connect_failed|proxy connect request failed|while connecting to .* via proxy|proxy-based connection establishment failed",
     "description": "The agent cannot reach the EPM service through the configured proxy."},
    {"name": "EPM TLS negotiation failures", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"aws_io_tls_\w+|aws_error_pkcs\w*|secure connection to fail",
     "description": "TLS setup to the EPM service failed. Check SSL inspection, trusted roots, and TLS versions."},
    {"name": "EPM DNS resolution failures", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"aws_io_dns_\w+|couldn'?t resolve host",
     "description": "The agent could not resolve the EPM service address."},
    {"name": "EPM socket timeouts and drops", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"aws_io_socket_\w+|aws_error_mqtt_unexpected_hangup|connection was closed unexpectedly",
     "description": "Connections to the EPM service time out or drop. Firewalls, routing, or network filtering can block the agent."},
    {"name": "EPM cloud client not connected", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"epm_result_err_client_not_connected|client is not connected|ng_iot: (connection_failure|disconnection)|connection failure lifecycle event|fetch \w+: not connected|reconnect after failure",
     "description": "The agent's cloud channel is down. Policy updates, events, and on-demand lookups wait until it reconnects."},
    {"name": "EPM manager address unreachable", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"getmanageraddress\w*:? (call )?failed|most likely a network error occurred|whatsup: lp: can'?t readbyte",
     "description": "The agent cannot reach the EPM dispatcher or manager endpoint."},
    {"name": "EPM server request errors", "severity": "medium", "platforms": ALL, "impact": "connectivity",
     "pattern": r"epm_result_err_(timeout|internal\w*|too_many_requests|canceled)",
     "description": "Requests to the EPM service time out, are throttled, or return internal errors."},
    {"name": "Event and inventory upload failures", "severity": "medium", "platforms": ALL, "impact": "connectivity",
     "pattern": r"failed to send (events|inventory|message)|failed to _sendinventoryinfo|failed to (decode|handle) incoming message",
     "description": "Audit events, inventory, or server commands are not delivered, so console data can be missing or stale."},
    {"name": "Registration and enrollment failures", "severity": "high", "platforms": ALL, "impact": "auth",
     "pattern": r"registration failed|received error from manager|vf_error_data|_writeenrollmentdata: error",
     "description": "The agent failed to register or enroll with the EPM service."},
    {"name": "PAM/NSS modules cannot reach the agent", "severity": "high", "platforms": LNX, "impact": "service",
     "pattern": r"can'?t connect to the epm agent",
     "description": "The EPM PAM or NSS module could not connect to the local agent. Logins, sudo, and user lookups can fail or fall back while the agent is down."},
    {"name": "Agent IPC failures", "severity": "high", "platforms": WIN, "impact": "service",
     "pattern": r"agent failed to connect to server|no connection from agent|_begincall failed|could not find vf_ipc_mon\.dll|failed to get handle to agent process|failed to open service \[vf_agent\]",
     "description": "Agent components cannot talk to the agent service. Elevation prompts and policy decisions can fail."},
    {"name": "Agent service control errors", "severity": "high", "platforms": ALL, "impact": "service",
     "pattern": r"openscmanager\(\) failed|unauthorized stop request|vfstopserviceevent\) failed|cvfagentmain::\w+: error|previous run: .*(reset by peer|crash|panic)",
     "description": "The agent service failed during startup, shutdown, or service control."},
    {"name": "Agent driver communication errors", "severity": "high", "platforms": WIN, "impact": "driver",
     "pattern": r"drv error|sendmessagetoport .* failed|_releasewaitinkernel",
     "description": "The agent service cannot exchange requests with its kernel driver, which can delay or skip process control."},
    {"name": "Agent configuration errors", "severity": "medium", "platforms": ALL, "impact": "config",
     "pattern": r"key is not present in hp config|shared config is empty|failed to serialize to|cvfqueryhiddenconfig::\w+: error|failed to read and store .*hidden params",
     "description": "Agent configuration or hidden parameters are missing or could not be stored."},
    {"name": "Integrity and signature check failures", "severity": "medium", "platforms": ALL, "impact": "config",
     "pattern": r"signature integrity check failed|validatexml failed|bcryptfinishhash failed|failed to check signature validity|gethashstringusing.*failed",
     "description": "File hashing or signature checks failed. Hash-based or publisher-based policy targets may not match."},
    {"name": "Entra ID and Azure lookup failures", "severity": "medium", "platforms": ALL, "impact": "identity",
     "pattern": r"azr:? +(error|warning)|azure-portal-authenticate: failed|authenticated: failed|microsoftgraphclienterror|no device with this name in entraid|failed authenticate in azure",
     "description": "The agent cannot query Entra ID, so policies targeted at cloud users or groups may not apply."},
    {"name": "IdP and MFA sign-in failures", "severity": "medium", "platforms": ALL, "impact": "auth",
     "pattern": r"mfa sign-in failed|totp validation failed|invalid totp format|auth code empty|idp: failed|idpcacheservices::\w+\(\) failed|failed to present idp sign-in|failed to update idp cache",
     "description": "Identity provider or MFA sign-in steps failed for elevation or JIT requests."},
    {"name": "User/group resolution timeouts", "severity": "high", "platforms": LNX, "impact": "identity",
     "pattern": r"nss: .*\btimeout\b|can'?t read nss message|cyberark-epm-nss.*(broken pipe|reset by peer|timeout)|epm-nss.*(reset by peer|so_error)|fetch the primary group of gid: \d+, timeout",
     "description": "User and group lookups through the agent time out. Logins, sudo, and id lookups can stall or fail."},
    {"name": "User/group not found", "severity": "low", "platforms": LNX, "impact": "identity",
     "pattern": r"resolve: (user|group) .*not found|group not found for gid|(uid|gid) is out of range|less than minimum allowed gid|contains unallowed characters|nss: user .*invalid user",
     "description": "Users or groups referenced by policies or logins could not be resolved."},
    {"name": "EPM sudo plugin failures", "severity": "high", "platforms": LNX, "impact": "elevation",
     "pattern": r"sudoers plugin has failed|can'?t list privileges|can'?t validate:|policy_check: .*failed",
     "description": "The EPM sudo plugin could not list, validate, or check privileges, so sudo requests can be denied."},
    {"name": "Preloader errors", "severity": "medium", "platforms": LNX, "impact": "elevation",
     "pattern": r"found preloader .* but not allowed by config|epmpreloader\[\d+\]: \S+ \S+ e \d+|\|preloader\|.*(error|fail)",
     "description": "The EPM preloader rejected a library or failed a system call, which can affect process control."},
    {"name": "Endpoint Security process lookups failed", "severity": "low", "platforms": MAC, "impact": "driver",
     "pattern": r"failed to get process \S+ (path|audit token)|failed to exclude process|failed to cache parent",
     "description": "The Endpoint Security extension could not inspect some processes; they may bypass policy evaluation."},
    {"name": "Coexisting privilege manager errors", "severity": "low", "platforms": LNX, "impact": "host",
     "pattern": r"\bpb(masterd|locald|run|logd|configd|replay)[\d.-]*\[\d+\]:.*(failure|failed|timed out|error|errno:[1-9])",
     "description": "Another privilege management product on the host reports errors and may conflict with sudo or PAM handling."},
    {"name": "Expired account passwords", "severity": "medium", "platforms": LNX + MAC, "impact": "host",
     "pattern": r"authentication token is no longer valid|unable to change expired password|authentication token manipulation error",
     "description": "PAM reports expired passwords for accounts used by scheduled jobs or sudo."},
]

GENERIC_RULES = [
    {"name": "MQTT communication errors", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"mqtt.*(error|fail|lost|refused|timeout|timed out|disconnect|unable)|(error|fail|lost|refused|timeout|disconnect|unable).*mqtt"},
    {"name": "Server/HTTPS communication failures", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"(https?|dispatcher|server|connection).*(fail|refused|unreachable|timed out|timeout|reset|status code 5\d\d)"},
    {"name": "TLS/certificate errors", "severity": "high", "platforms": ALL, "impact": "connectivity",
     "pattern": r"(ssl|tls|certificate|x509|handshake).*(error|fail|invalid|expired|untrusted|revoked)"},
    {"name": "DNS resolution failures", "severity": "medium", "platforms": ALL, "impact": "connectivity",
     "pattern": r"(dns|resolve|host ?name|getaddrinfo).*(fail|error|not found|unknown)|name or service not known|no such host"},
    {"name": "Proxy errors", "severity": "medium", "platforms": ALL, "impact": "connectivity",
     "pattern": r"proxy.*(error|fail|refused|auth|407)"},
    {"name": "Policy download/parse failures", "severity": "high", "platforms": ALL, "impact": "policy",
     "pattern": r"polic(y|ies).*(fail|error|invalid|corrupt|could not|cannot|unable)"},
    {"name": "Service start failures/crashes", "severity": "high", "platforms": ALL, "impact": "service",
     "pattern": r"(service|daemon|agent).*(failed to start|crash|terminated unexpectedly|stopped unexpectedly|core dump|segfault)|segmentation fault"},
    {"name": "Driver/kernel extension load errors", "severity": "high", "platforms": ALL, "impact": "driver",
     "pattern": r"(driver|minifilter|filter manager|kext|system extension|kernel module).*(fail|error|not loaded|could not|denied)"},
    {"name": "Access denied", "severity": "medium", "platforms": ALL, "impact": "host",
     "pattern": r"access (is )?denied|permission denied|operation not permitted|0x80070005"},
    {"name": "Disk/database errors", "severity": "medium", "platforms": ALL, "impact": "host",
     "pattern": r"sqlite.*(error|fail|corrupt|locked)|database (is )?(locked|corrupt|malformed)|disk (is )?full|no space left"},
    {"name": "License/registration errors", "severity": "high", "platforms": ALL, "impact": "auth",
     "pattern": r"(licen[cs]e|registration|register|enroll).*(fail|error|invalid|expired|denied)"},
    {"name": "Generic ERROR/FATAL/Exception", "severity": "low", "platforms": ALL, "impact": "general",
     "pattern": r"\b(error|fatal|critical)\b|exception"},
]

RULES = STATUS_RULES + EPM_SPECIFIC_RULES + GENERIC_RULES

PROCMON_RESULTS = ["ACCESS DENIED", "NAME NOT FOUND", "PATH NOT FOUND", "SHARING VIOLATION",
                   "NAME COLLISION", "INVALID PARAMETER", "PRIVILEGE NOT HELD", "BAD NETWORK PATH"]


def compiled(platform):
    out = []
    for r in RULES:
        if platform in r["platforms"] or platform == "unknown":
            files = re.compile(r["files"], re.IGNORECASE) if r.get("files") else None
            out.append(dict(r, regex=re.compile(r["pattern"]), files=files))
    return out


def for_file(rules, name):
    return [r for r in rules if r["files"] is None or r["files"].search(name)]


def impact_label(key):
    return IMPACTS.get(key, IMPACTS["general"])
