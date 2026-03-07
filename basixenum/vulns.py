from __future__ import annotations

import re
from typing import Any


def analyze_services(port_entries: list[dict]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for entry in port_entries:
        service = (entry.get("service") or "").lower()
        version = (entry.get("version") or "").strip()
        port = entry.get("port")
        proto = entry.get("proto")

        product = _guess_product(service, version)

        results.append(
            {
                "port": port,
                "proto": proto,
                "service": service or "unknown",
                "product": product,
                "version": version or "unknown",
                "confidence": _confidence(service, version, product),
                "possible_vuln_matches": _possible_vuln_matches(service, version, product),
                "misconfig_checks": _misconfig_checks(service, port, product),
                "next_manual_checks": _next_manual_checks(service, port, product),
                "why_it_matters": _why_it_matters(service, port, product),
            }
        )

    return results


def _guess_product(service: str, version: str) -> str:
    blob = f"{service} {version}".lower()

    if "apache" in blob:
        return "Apache httpd"
    if "squid" in blob:
        return "Squid"
    if "vsftpd" in blob:
        return "vsftpd"
    if "openssh" in blob:
        return "OpenSSH"
    if "samba" in blob or "smbd" in blob:
        return "Samba"

    if service == "http-proxy":
        return "HTTP Proxy"
    if service == "http":
        return "HTTP Service"
    if service == "ftp":
        return "FTP Service"
    if service == "ssh":
        return "SSH Service"

    return service or "unknown"


def _extract_version_number(text: str) -> str | None:
    if not text:
        return None
    m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", text)
    return m.group(1) if m else None


def _version_tuple(v: str | None) -> tuple[int, ...]:
    if not v:
        return ()
    parts = []
    for chunk in v.split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts)


def _confidence(service: str, version: str, product: str) -> str:
    blob = f"{service} {version}".lower()

    if product in {"Apache httpd", "Squid", "vsftpd"} and _extract_version_number(blob):
        return "high"

    if product == "OpenSSH":
        # Banner often includes distro backports, so specific matching is less reliable.
        return "medium"

    if product == "Samba":
        # "Samba smbd 4" is broad and noisy.
        ver = _extract_version_number(blob)
        if ver and ver.count(".") >= 1:
            return "medium"
        return "low"

    if version and version.lower() != "unknown":
        return "medium"

    return "low"


def _possible_vuln_matches(service: str, version: str, product: str) -> list[str]:
    blob = f"{service} {version}".lower()
    ver = _extract_version_number(blob)
    vt = _version_tuple(ver)

    matches: list[str] = []

    if product == "Apache httpd":
        if vt and vt <= (2, 4, 49):
            matches.append(
                "Apache 2.4.x family may include path traversal / file disclosure-era issues in older branches. Manual verification required."
            )
        if vt and vt <= (2, 4, 50):
            matches.append(
                "Apache 2.4.x family may include RCE-adjacent follow-on issues in affected legacy releases. Manual verification required."
            )
        matches.append(
            "Review Apache httpd 2.4.x version-specific findings and loaded modules before treating any match as actionable."
        )

    elif product == "Squid":
        matches.append(
            "Review Squid 4.x proxy version for historical cache/proxy handling weaknesses and access-control-related issues. Manual verification required."
        )
        matches.append(
            "Prioritize proxy exposure and ACL misconfiguration testing before spending time on version-only leads."
        )

    elif product == "vsftpd":
        if vt and vt >= (3, 0, 0):
            matches.append(
                "No famous high-confidence static match stands out from the banner alone for modern vsftpd 3.x. Focus on anonymous access, writable locations, and local misconfigurations."
            )
        else:
            matches.append(
                "Older vsftpd branches may have known historical issues, but the banner alone is not enough to confirm exploitable exposure."
            )

    elif product == "OpenSSH":
        matches.append(
            "OpenSSH banners on Linux distributions often reflect backported patches. Treat raw version matching cautiously and verify distro-specific fixes manually."
        )
        matches.append(
            "Prioritize authentication surface, allowed methods, weak credentials, and key reuse over generic version-only CVE hunting."
        )

    elif product == "Samba":
        matches.append(
            "Samba family detected, but the banner is broad. Review Samba 4.x family issues carefully because generic major-version matches produce false positives."
        )
        matches.append(
            "Misconfiguration and share-permission weaknesses are more reliable early leads than version-only assumptions here."
        )

    elif "http" in blob:
        matches.append(
            "HTTP service detected, but no strong product fingerprint is available yet. Fingerprint the stack further before mapping version-based issues."
        )

    if not matches:
        matches.append("No strong static version-based matches yet. Manual verification required.")

    return matches


def _misconfig_checks(service: str, port: int | None, product: str) -> list[str]:
    s = (service or "").lower()

    if s == "ftp" or product == "vsftpd":
        return [
            "Test anonymous login",
            "Check for writable upload access",
            "Inspect accessible files and permissions",
        ]

    if s == "http-proxy" or product == "Squid":
        return [
            "Test whether the proxy behaves like an open proxy",
            "Check proxy ACL restrictions and reachable destinations",
            "Review response behavior for internal/resource fetching abuse",
        ]

    if s in ("http", "https") or product in {"Apache httpd", "HTTP Service"}:
        return [
            "Check for admin panels, login portals, and default credentials",
            "Check for directory listing and exposed files",
            "Fingerprint technologies, headers, cookies, and framework clues",
        ]

    if s in ("netbios-ssn", "microsoft-ds", "smb") or product == "Samba":
        return [
            "Test null/guest access",
            "Enumerate shares and permissions",
            "Check for writable shares",
        ]

    if s == "ssh" or product == "OpenSSH":
        return [
            "Review authentication methods",
            "Check for weak credential paths only if in scope",
            "Note distro/package context before trusting version-only matches",
        ]

    return ["Review service manually for weak configuration"]


def _next_manual_checks(service: str, port: int | None, product: str) -> list[str]:
    s = (service or "").lower()

    if s == "ftp" or product == "vsftpd":
        return [
            f"Run manual FTP login tests against port {port}",
            "List files and test upload if permitted",
        ]

    if s == "http" or product in {"Apache httpd", "HTTP Service"}:
        return [
            f"Browse the web service on port {port}",
            "Check title, headers, robots.txt, and run directory enumeration",
        ]

    if s == "http-proxy" or product == "Squid":
        return [
            f"Test whether port {port} behaves like an open proxy",
            "Check proxy ACL behavior with manual requests",
            "Try controlled outbound fetch behavior if allowed in scope",
        ]

    if s in ("netbios-ssn", "microsoft-ds", "smb") or product == "Samba":
        return [
            "Run SMB enumeration for shares, users, and access level",
            "Test guest/null session behavior",
        ]

    if s == "ssh" or product == "OpenSSH":
        return [
            "Check banner and allowed auth methods",
            "Deprioritize unless credentials or stronger leads appear",
        ]

    return ["Perform focused manual enumeration"]


def _why_it_matters(service: str, port: int | None, product: str) -> str:
    s = (service or "").lower()

    if s == "ftp" or product == "vsftpd":
        return "FTP often leads to file access, anonymous login, or writable upload abuse."

    if s == "http" or product in {"Apache httpd", "HTTP Service"}:
        return "Web services often expose the main attack surface and deserve early attention."

    if s == "http-proxy" or product == "Squid":
        return "A misconfigured proxy can expose internal access paths or proxy abuse."

    if s in ("netbios-ssn", "microsoft-ds", "smb") or product == "Samba":
        return "SMB frequently reveals shares, weak permissions, or authentication issues."

    if s == "ssh" or product == "OpenSSH":
        return "SSH is usually credential-driven, but version and auth details still matter."

    return "This service may provide an additional attack path."
