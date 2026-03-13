from pathlib import Path


FOCUS_MAP = {
    "WEB": {"ports": {80, 443, 8080, 8443, 8000, 8888, 3128, 3333}},
    "SMB": {"ports": {139, 445}},
    "WINRM": {"ports": {5985, 5986}},
    "RDP": {"ports": {3389}},
    "DNS": {"ports": {53}},
    "LDAP": {"ports": {389, 636}},
    "KERBEROS": {"ports": {88}},
    "RPC": {"ports": {111, 135}},
    "NFS": {"ports": {2049}},
    "MAIL": {"ports": {25, 110, 143, 465, 587, 993, 995}},
}

SUSPICIOUS_PORTS = {
    21: "FTP exposed",
    23: "Telnet exposed",
    2375: "Docker API exposed",
    2376: "Docker TLS API exposed",
    3128: "Proxy service exposed",
    3306: "MySQL exposed",
    3333: "Unusual web/admin/custom app port",
    3389: "RDP exposed",
    4444: "Common handler/backdoor/testing port",
    45000: "Unusual high port, verify custom service",
    47001: "Windows Remote Management service",
    5432: "PostgreSQL exposed",
    5601: "Kibana exposed",
    6379: "Redis exposed",
    8009: "AJP exposed",
    9200: "Elasticsearch exposed",
    11211: "Memcached exposed",
    27017: "MongoDB exposed",
    50000: "Custom/admin service, investigate manually",
}


def _is_web_entry(entry: dict) -> bool:
    blob = f"{entry['service']} {entry['version']}".lower()
    return (
        entry["port"] in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333}
        or "http" in entry["service"].lower()
        or "apache" in blob
        or "nginx" in blob
        or "iis" in blob
        or "squid" in blob
    )


def _is_proxy_entry(entry: dict) -> bool:
    blob = f"{entry['service']} {entry['version']}".lower()
    return "proxy" in entry["service"].lower() or "squid" in blob or entry["port"] == 3128


def _get_primary_web_entry(port_entries: list[dict]) -> dict | None:
    web_entries = [e for e in port_entries if _is_web_entry(e)]
    if not web_entries:
        return None

    app_candidates = [e for e in web_entries if not _is_proxy_entry(e)]
    if app_candidates:
        preferred_ports = [80, 443, 8080, 8443, 8000, 8888, 3333]
        for port in preferred_ports:
            for entry in app_candidates:
                if entry["port"] == port:
                    return entry
        return app_candidates[0]

    return web_entries[0]


def detect_focus_labels(port_entries: list[dict]) -> list[str]:
    detected = set()
    ports = {e["port"] for e in port_entries}

    for label, meta in FOCUS_MAP.items():
        if ports & meta["ports"]:
            detected.add(label)

    for entry in port_entries:
        service = entry["service"].lower()
        version = entry["version"].lower()

        if "http" in service or "apache" in version or "nginx" in version or "iis" in version or "squid" in version:
            detected.add("WEB")

        if "smb" in service or "netbios" in service or "samba" in version:
            detected.add("SMB")

        if "ldap" in service:
            detected.add("LDAP")

        if "kerberos" in service:
            detected.add("KERBEROS")

    ad_needed = {"KERBEROS", "LDAP", "SMB", "DNS"}
    if ad_needed.issubset(detected):
        detected.add("ACTIVE_DIRECTORY_LIKELY")

    return sorted(detected)


def guess_target_type(port_entries: list[dict]) -> str:
    ports = {entry["port"] for entry in port_entries}
    services = " ".join(f'{e["service"]} {e["version"]}'.lower() for e in port_entries)

    if {88, 389, 445}.issubset(ports) or "microsoft" in services or "windows" in services:
        return "Windows / Active Directory likely"
    if "apache" in services or "openssh" in services or "nginx" in services or "ubuntu" in services:
        return "Linux / Unix-like likely"
    if "http" in services or 80 in ports or 443 in ports or 8080 in ports or 8443 in ports or 3128 in ports or 3333 in ports:
        return "Web server / application host likely"
    return "Unknown"


def summarize_services(port_entries: list[dict]) -> list[str]:
    summaries = []

    for entry in port_entries:
        port = entry["port"]
        service = entry["service"].lower()
        version = entry["version"].lower()

        if port in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333} or "http" in service or "apache" in version or "nginx" in version or "squid" in version:
            summaries.append(
                f"HTTP ({port}/{entry['proto']}): Web attack surface detected. "
                f"Recommended: browser review, ffuf/gobuster, tech fingerprinting, manual auth testing."
            )
        elif port in {139, 445} or "microsoft-ds" in service or "netbios" in service or "smb" in service or "samba" in version:
            summaries.append(
                f"SMB ({port}/{entry['proto']}): Windows file-sharing surface detected. "
                f"Recommended: netexec smb, smbclient, signing/null session/share enumeration."
            )
        elif port in {22} or service == "ssh":
            summaries.append(
                f"SSH ({port}/{entry['proto']}): Remote shell service exposed. "
                f"Recommended: auth method checks, version review, credential testing if in scope."
            )
        elif port in {21} or service == "ftp":
            summaries.append(
                f"FTP ({port}/{entry['proto']}): File transfer service exposed. "
                f"Recommended: test anonymous login, inspect banners, review writable locations."
            )
        elif port in {53} or service == "domain":
            summaries.append(
                f"DNS ({port}/{entry['proto']}): Name service exposed. "
                f"Recommended: version review, zone transfer check, DNS recon."
            )
        elif port in {88} or "kerberos" in service:
            summaries.append(
                f"Kerberos ({port}/{entry['proto']}): Strong Active Directory signal. "
                f"Recommended: confirm domain environment, account/user enumeration if allowed."
            )
        elif port in {389, 636} or "ldap" in service:
            summaries.append(
                f"LDAP ({port}/{entry['proto']}): Directory service exposed. "
                f"Recommended: anonymous bind checks, domain discovery, AD triage."
            )
        elif port in {5985, 5986} or "wsman" in service:
            summaries.append(
                f"WinRM ({port}/{entry['proto']}): Remote Windows management exposed. "
                f"Recommended: identify valid creds path, confirm domain/local auth options."
            )
        elif port in {3389} or "ms-wbt-server" in service:
            summaries.append(
                f"RDP ({port}/{entry['proto']}): Remote desktop service exposed. "
                f"Recommended: NLA review, credential path checks, screenshot/login testing if allowed."
            )
        else:
            summaries.append(
                f"{entry['service']} ({port}/{entry['proto']}): Service exposed. "
                f"Recommended: banner review, version triage, protocol-specific enumeration."
            )

    return summaries


def build_interesting_findings(port_entries: list[dict], focus_labels: list[str]) -> list[str]:
    findings = []

    if focus_labels:
        findings.append("Focus Radar signals: " + ", ".join(focus_labels))

    ports = {e["port"] for e in port_entries}
    services_blob = " ".join(f"{e['service']} {e['version']}".lower() for e in port_entries)

    if (
        any(p in ports for p in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333})
        or "http" in services_blob
        or "apache" in services_blob
        or "nginx" in services_blob
        or "squid" in services_blob
    ):
        findings.append("Web service detected. Initial web enumeration should be prioritized.")

    if any(p in ports for p in {139, 445}) or "samba" in services_blob or "netbios" in services_blob:
        findings.append("SMB exposed. Check shares, signing, anonymous access, and domain clues.")

    if {88, 389, 445}.issubset(ports):
        findings.append("Port combination strongly suggests Active Directory-related target.")

    if ports == {22}:
        findings.append("Single exposed service: SSH. Possible minimal attack surface or hardened host.")

    suspicious = [f"{p}: {desc}" for p, desc in SUSPICIOUS_PORTS.items() if p in ports]
    findings.extend(suspicious)

    if not findings:
        findings.append("No high-signal findings yet. Continue with service-by-service triage.")

    return findings


def build_possible_vuln_matches(port_entries: list[dict]) -> list[str]:
    matches = []

    for entry in port_entries:
        product = entry["version"].strip()
        if not product:
            continue

        matches.append(
            f"{entry['port']}/{entry['proto']} {entry['service']}: "
            f"Possible vulnerability matches for '{product}'. Manual verification required."
        )

    if not matches:
        matches.append("No version strings extracted cleanly enough for version-based matching yet.")

    return matches


def build_recommended_next_steps(port_entries: list[dict], focus_labels: list[str]) -> list[str]:
    steps = []
    ports = {e["port"] for e in port_entries}
    services_blob = " ".join(f"{e['service']} {e['version']}".lower() for e in port_entries)

    if (
        any(p in ports for p in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333})
        or "http" in services_blob
        or "apache" in services_blob
        or "nginx" in services_blob
        or "iis" in services_blob
        or "squid" in services_blob
    ):
        steps.append("Web: review site manually, inspect headers, identify framework, run ffuf/gobuster.")

    if any(p in ports for p in {139, 445}) or "samba" in services_blob or "netbios" in services_blob:
        steps.append("SMB: run netexec smb and smbclient enumeration, inspect signing and shares.")

    if 53 in ports:
        steps.append("DNS: attempt DNS recon and zone transfer checks where appropriate.")

    if any(p in ports for p in {88, 389, 636, 5985, 5986}):
        steps.append("AD/Windows: validate domain indicators, users, auth paths, and remote management exposure.")

    if 22 in ports or "ssh" in services_blob:
        steps.append("SSH: inspect auth methods and banner details, test credentials only if in scope.")

    if 21 in ports or "ftp" in services_blob:
        steps.append("FTP: test anonymous login, inspect banners, and review writable areas if present.")

    if "ACTIVE_DIRECTORY_LIKELY" in focus_labels:
        steps.append("AD likely: prioritize host naming, LDAP/Kerberos checks, SMB enumeration, and domain mapping.")

    if not steps:
        steps.append("Enumerate each discovered service manually based on protocol and banner details.")

    return steps


def build_attack_priority(port_entries: list[dict], service_analysis: list[dict] | None = None) -> list[str]:
    ranked: list[tuple[int, str]] = []
    primary_web = _get_primary_web_entry(port_entries)

    for entry in port_entries:
        port = entry["port"]
        proto = entry["proto"]
        service = entry["service"]
        version = entry["version"]
        blob = f"{service} {version}".lower()

        if primary_web and entry is primary_web:
            ranked.append((1, f"Port {port}/{proto} ({service}): Primary web application target"))
        elif port == 3128 or "squid" in blob or "proxy" in service.lower():
            ranked.append((2, f"Port {port}/{proto} ({service}): Check proxy abuse / ACL weakness"))
        elif port in {139, 445} or "samba" in blob or "netbios" in service.lower() or "smb" in service.lower():
            ranked.append((3, f"Port {port}/{proto} ({service}): Enumerate shares and weak access"))
        elif port == 21 or "vsftpd" in blob or service.lower() == "ftp":
            ranked.append((4, f"Port {port}/{proto} ({service}): Test anonymous login and writable paths"))
        elif port == 22 or "openssh" in blob or service.lower() == "ssh":
            ranked.append((5, f"Port {port}/{proto} ({service}): Credential-driven, lower priority"))
        else:
            ranked.append((6, f"Port {port}/{proto} ({service}): Manual review required"))

    ranked.sort(key=lambda x: x[0])
    return [item[1] for item in ranked]


def build_likely_initial_attack_path(port_entries: list[dict]) -> list[str]:
    steps = []
    ports = {e["port"] for e in port_entries}
    blob = " ".join(f"{e['service']} {e['version']}".lower() for e in port_entries)
    primary_web = _get_primary_web_entry(port_entries)

    if primary_web:
        steps.append(f"Enumerate the web application on port {primary_web['port']}")
    if 3128 in ports or "squid" in blob or "proxy" in blob:
        steps.append("Test Squid/proxy exposure for open proxy behavior or ACL abuse")
    if 139 in ports or 445 in ports or "samba" in blob or "netbios" in blob:
        steps.append("Enumerate SMB shares, permissions, and guest/null access")
    if 21 in ports or "ftp" in blob or "vsftpd" in blob:
        steps.append("Test FTP for anonymous access and writable locations")
    if 22 in ports or "ssh" in blob or "openssh" in blob:
        steps.append("Revisit SSH only if credentials or stronger leads appear")

    if not steps:
        steps.append("No clear attack path yet. Continue service-by-service enumeration.")

    return steps


def build_quick_wins(port_entries: list[dict], focus_labels: list[str], service_analysis: list[dict] | None = None) -> list[str]:
    wins = []
    ports = {e["port"] for e in port_entries}
    services_blob = " ".join(f"{e['service']} {e['version']}".lower() for e in port_entries)

    if (
        any(p in ports for p in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333})
        or "http" in services_blob
        or "apache" in services_blob
        or "nginx" in services_blob
        or "iis" in services_blob
        or "squid" in services_blob
    ):
        web_ports = []
        for e in port_entries:
            blob = f"{e['service']} {e['version']}".lower()
            if e["port"] in {80, 443, 8080, 8443, 8000, 8888, 3128, 3333} or "http" in blob or "apache" in blob or "nginx" in blob or "iis" in blob or "squid" in blob:
                web_ports.append(str(e["port"]))
        if web_ports:
            wins.append(f"Browse web-facing ports first: {', '.join(sorted(set(web_ports), key=int))}.")

    if any(e["port"] == 3128 or "squid" in f"{e['service']} {e['version']}".lower() for e in port_entries):
        wins.append("Test whether the proxy service behaves like an open proxy or has weak ACL restrictions.")

    if any(p in ports for p in {139, 445}) or "samba" in services_blob or "netbios" in services_blob:
        wins.append("Run quick SMB enumeration for shares, guest/null access, and signing.")

    if 21 in ports or "ftp" in services_blob:
        wins.append("Test anonymous FTP login immediately.")

    if "ACTIVE_DIRECTORY_LIKELY" in focus_labels:
        wins.append("Treat the host as AD-related and prioritize SMB, LDAP, Kerberos, and naming clues together.")

    if service_analysis:
        for item in service_analysis:
            if item.get("confidence") == "high" and item.get("possible_vuln_matches"):
                wins.append(
                    f"Review high-confidence version clues on {item.get('port')}/{item.get('proto')} {item.get('service')}."
                )

    if not wins:
        wins.append("No immediate quick wins detected. Proceed with normal per-service enumeration.")

    deduped = []
    seen = set()
    for item in wins:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def build_web_triage(port_entries: list[dict]) -> dict | None:
    web_entries = [entry for entry in port_entries if _is_web_entry(entry)]

    if not web_entries:
        return None

    primary = _get_primary_web_entry(port_entries)
    other = [e for e in web_entries if e is not primary]

    primary_role = _guess_web_role(primary)
    other_services = [f"{e['port']}/{e['proto']} {e['service']} {e['version']}".strip() for e in other]

    what_to_check_first = [
        f"Browse the primary web target on port {primary['port']}",
        "Inspect title, headers, redirects, cookies, and tech fingerprints",
        "Check robots.txt and run directory/content enumeration",
    ]

    quick_wins = []
    if primary["port"] != 3128:
        quick_wins.append(f"Prioritize the app/site on port {primary['port']} before secondary web services.")
    if any(e["port"] == 3128 or "squid" in f"{e['service']} {e['version']}".lower() for e in web_entries):
        quick_wins.append("Test proxy ACL exposure and open proxy behavior on port 3128.")
    if any("apache" in f"{e['service']} {e['version']}".lower() for e in web_entries):
        quick_wins.append("Fingerprint Apache-exposed content and check for common admin/content paths.")

    possible_matches = []
    for e in web_entries:
        blob = f"{e['service']} {e['version']}".strip()
        if blob.strip():
            possible_matches.append(
                f"{e['port']}/{e['proto']} {e['service']}: Possible version-based web matches for '{e['version']}'. Manual verification required."
            )

    why_it_matters = (
        "Web services often provide the most accessible attack surface, while proxies may introduce ACL or routing weaknesses."
    )

    return {
        "primary_web_target": f"{primary['port']}/{primary['proto']} {primary['service']} {primary['version']}".strip(),
        "other_web_services": other_services,
        "likely_role": primary_role,
        "what_to_check_first": what_to_check_first,
        "quick_wins": quick_wins or ["Review the primary web target manually."],
        "possible_vulnerability_matches": possible_matches or ["No strong web version clues yet. Manual verification required."],
        "why_it_matters": why_it_matters,
    }


def _guess_web_role(entry: dict) -> str:
    blob = f"{entry['service']} {entry['version']}".lower()

    if "proxy" in entry["service"].lower() or "squid" in blob or entry["port"] == 3128:
        return "Proxy service likely"
    if "apache" in blob or "nginx" in blob or "iis" in blob:
        return "Web application / site likely"
    if "http" in entry["service"].lower():
        return "HTTP service detected"
    return "Web-facing service detected"


def render_service_analysis(service_analysis: list[dict] | None) -> list[str]:
    lines = []

    if not service_analysis:
        lines.append("No per-service analysis available yet.")
        return lines

    for item in service_analysis:
        lines.append(f"Service: {item.get('service', 'unknown')}")
        lines.append(f"Port: {item.get('port', 'unknown')}/{item.get('proto', 'unknown')}")
        lines.append(f"Product: {item.get('product', 'unknown')}")
        lines.append(f"Version: {item.get('version', 'unknown')}")
        lines.append(f"Confidence: {item.get('confidence', 'unknown')}")
        lines.append("")

        lines.append("  Possible Vulnerability Matches:")
        for match in item.get("possible_vuln_matches", []) or ["No version-based matches yet."]:
            lines.append(f"  - {match}")

        lines.append("  Likely Misconfig Checks:")
        for check in item.get("misconfig_checks", []) or ["No misconfiguration checks defined yet."]:
            lines.append(f"  - {check}")

        lines.append("  Recommended Next Manual Checks:")
        for check in item.get("next_manual_checks", []) or ["No manual checks defined yet."]:
            lines.append(f"  - {check}")

        lines.append("  Why It Matters:")
        lines.append(f"  - {item.get('why_it_matters', 'No rationale provided.')}")
        lines.append("")
        lines.append("-" * 30)

    if lines and lines[-1] == "-" * 30:
        lines.pop()

    return lines


def render_triage_report(
    target: str,
    mode: str,
    outdir: Path,
    port_entries: list[dict],
    scan_time: str,
    service_analysis: list[dict] | None = None,
) -> str:
    focus_labels = detect_focus_labels(port_entries)
    target_guess = guess_target_type(port_entries)
    service_names = sorted({e["service"] for e in port_entries})
    web_triage = build_web_triage(port_entries)
    quick_wins = build_quick_wins(port_entries, focus_labels, service_analysis)
    attack_priority = build_attack_priority(port_entries, service_analysis)
    likely_attack_path = build_likely_initial_attack_path(port_entries)

    lines = []
    lines.append("=" * 40)
    lines.append("BasiXenuM Scan Triage Report")
    lines.append(f"Target: {target}")
    lines.append(f"Scan Time: {scan_time}")
    lines.append(f"Mode: {mode}")
    lines.append("=" * 40)
    lines.append("")

    lines.append("TARGET INFORMATION")
    lines.append("------------------")
    lines.append(f"Target: {target}")
    lines.append(f"Outdir: {outdir}")
    lines.append(f"Detected Services: {', '.join(service_names) if service_names else 'none (no open ports discovered)'}")
    lines.append(f"Target Guess: {target_guess}")
    lines.append("")

    lines.append("OPEN PORTS")
    lines.append("----------")
    if port_entries:
        for entry in port_entries:
            version = f" {entry['version']}" if entry["version"] else ""
            lines.append(f"{entry['port']}/{entry['proto']:<4} {entry['service']}{version}")
    else:
        lines.append("No open ports found.")
    lines.append("")

    lines.append("SERVICE SUMMARY")
    lines.append("---------------")
    for item in summarize_services(port_entries):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("INTERESTING FINDINGS")
    lines.append("--------------------")
    for item in build_interesting_findings(port_entries, focus_labels):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("ATTACK PRIORITY")
    lines.append("---------------")
    for item in attack_priority:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("LIKELY INITIAL ATTACK PATH")
    lines.append("--------------------------")
    for item in likely_attack_path:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("QUICK WINS")
    lines.append("----------")
    for item in quick_wins:
        lines.append(f"- {item}")
    lines.append("")

    if web_triage:
        lines.append("WEB TRIAGE")
        lines.append("----------")
        lines.append(f"Primary Web Target: {web_triage['primary_web_target']}")
        lines.append(
            "Other Web Services: "
            + (", ".join(web_triage["other_web_services"]) if web_triage["other_web_services"] else "None")
        )
        lines.append(f"Likely Role: {web_triage['likely_role']}")
        lines.append("What To Check First:")
        for item in web_triage["what_to_check_first"]:
            lines.append(f"- {item}")
        lines.append("Quick Wins:")
        for item in web_triage["quick_wins"]:
            lines.append(f"- {item}")
        lines.append("Possible Vulnerability Matches:")
        for item in web_triage["possible_vulnerability_matches"]:
            lines.append(f"- {item}")
        lines.append("Why It Matters:")
        lines.append(f"- {web_triage['why_it_matters']}")
        lines.append("")

    lines.append("POSSIBLE VULNERABILITY MATCHES")
    lines.append("------------------------------")
    for item in build_possible_vuln_matches(port_entries):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("SERVICE ANALYSIS")
    lines.append("----------------")
    for item in render_service_analysis(service_analysis):
        lines.append(item)
    lines.append("")

    lines.append("RECOMMENDED NEXT STEPS")
    lines.append("----------------------")
    for item in build_recommended_next_steps(port_entries, focus_labels):
        lines.append(f"- {item}")
    lines.append("")

    return "\n".join(lines)
